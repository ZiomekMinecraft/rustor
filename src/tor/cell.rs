const CELL_BODY_LEN: usize = 509;

// trait for serializing and deserializing tor objects
#[allow(dead_code)]
trait TorSerializer {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8], version: u8) -> Result<Self, &'static str> where Self: Sized;
}

// CircidLen is a enum that holds the circuit id length
#[derive(Debug, Clone, PartialEq)]
enum CircidLen{
    LEGACY(u16),
    MODERN(u32)
}

impl Default for CircidLen {
    fn default() -> Self {
        CircidLen::MODERN(0)
    }
    
}

// CellBody is a enum that holds the cell body
#[derive(Debug, Clone, PartialEq)]
enum CellBody {
    Fixed([u8; CELL_BODY_LEN]),
    VariableLenght(u16, Vec<u8>)
}

impl Default for CellBody {
    fn default() -> Self {
        CellBody::Fixed([0; CELL_BODY_LEN])
    }
}

// CellCommand is a enum that holds the cell command
#[derive(Debug, Clone, PartialEq, Default)]
#[allow(non_camel_case_types, dead_code)]
enum CellCommand {
    Unknown = -1,
    // FIXED
    #[default]
    PADDING = 0,          // circuit_id is 0
    CREATE = 1,             // Must be specified circ_id
    CREATED = 2,            // Must be specified circ_id
    RELAY = 3,              // Must be specified circ_id
    DESTROY = 4,            // Must be specified circ_id
    CREATE_FAST = 5,        // Must be specified circ_id
    CREATED_FAST = 6,       // Must be specified circ_id
    NETINFO = 8,          // circuit_id is 0
    RELAY_EARLY = 9,        // Must be specified circ_id
    CREATE2 = 10,           // Must be specified circ_id
    CREATED2 = 11,          // Must be specified circ_id
    PADDING_NEGOTIATE = 12, // Must be specified circ_id  only for v5 and above

    // VARIABLE
    VERSIONS = 7,         // circuit_id is 0
    VPADDING = 128,       // circuit_id is 0
    CERTS = 129,          // circuit_id is 0
    AUTH_CHALLENGE = 130, // circuit_id is 0
    AUTHENTICATE = 131,   // circuit_id is 0
    // AUTHORIZE = 132,      // circuit_id is 0   Not used yet
}

impl TorSerializer for CellCommand {
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.to_owned() as u8]
    }
    fn from_bytes(bytes: &[u8], _: u8) -> Result<Self, &'static str> where Self: Sized {
        match CellCommand::from(bytes[0]) {
            CellCommand::Unknown => Err("Unknown command"),
            command => Ok(command)
        } 
    }
}

impl From<u8> for CellCommand {
    fn from(num: u8) -> Self {
        match num {
            0 => CellCommand::PADDING,
            1 => CellCommand::CREATE,
            2 => CellCommand::CREATED,
            3 => CellCommand::RELAY,
            4 => CellCommand::DESTROY,
            5 => CellCommand::CREATE_FAST,
            6 => CellCommand::CREATED_FAST,
            7 => CellCommand::VERSIONS,
            8 => CellCommand::NETINFO,
            9 => CellCommand::RELAY_EARLY,
            10 => CellCommand::CREATE2,
            11 => CellCommand::CREATED2,
            12 => CellCommand::PADDING_NEGOTIATE,
            128 => CellCommand::VPADDING,
            129 => CellCommand::CERTS,
            130 => CellCommand::AUTH_CHALLENGE,
            131 => CellCommand::AUTHENTICATE,
            _ => CellCommand::Unknown
        }
    }
    
}

// Cell is a struct that holds the cell
#[derive(Debug, Clone, PartialEq, Default)]
struct Cell{
    circ_id: CircidLen,
    command: CellCommand,
    body: CellBody
}

impl Cell {
    fn new(circ_id: CircidLen, command: CellCommand, body: CellBody) -> Self {
        Cell {
            circ_id,
            command,
            body
        }
    }
}

impl TorSerializer for Cell {

    #[allow(dead_code)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        match &self.circ_id {
            CircidLen::LEGACY(circ_id) => {
                bytes.extend_from_slice(&circ_id.to_be_bytes());
            },
            CircidLen::MODERN(circ_id) => {
                bytes.extend_from_slice(&circ_id.to_be_bytes());
            }
        }

        let command_bytes = self.command.to_bytes().first().unwrap().to_owned();
        bytes.extend_from_slice(&[command_bytes]);

        match &self.body {
            CellBody::Fixed(body) => {
                bytes.extend_from_slice(body);
            },
            CellBody::VariableLenght(body_len, body) => {
                bytes.extend_from_slice(&body_len.to_be_bytes());
                bytes.extend_from_slice(body);
            }
        }

        bytes
    }
    
    #[allow(dead_code)]
    fn from_bytes(bytes: &[u8], version: u8) -> Result<Self, &'static str> {

        let mut ptr = 0;

        let circ_id = match version < 4 {
            true => {
                let circid_len = CircidLen::LEGACY(u16::from_be_bytes([bytes[ptr], bytes[ptr+1]]));
                ptr += 2;
                circid_len
            },
            false => {
                let circid_len = CircidLen::MODERN(
                    u32::from_be_bytes([bytes[ptr], bytes[ptr+1], bytes[ptr+2], bytes[ptr+3]]));
                ptr += 4;
                circid_len
            }
        };

        let command_num = bytes[ptr];
        ptr += 1;

        let command =  match CellCommand::from(command_num) {
            CellCommand::Unknown => return Err("Get command failed"),
            command => command
        };

        let body: CellBody = {
            if command_num < 128 && command_num != 7 {
                // Fixed cell length
                CellBody::Fixed(bytes[ptr..].try_into().unwrap())
            } else {
                // Variable cell length
                let body_len = u16::from_be_bytes([bytes[ptr], bytes[ptr+1]]);
                ptr += 2;
                CellBody::VariableLenght(body_len, bytes[ptr..(body_len as usize + ptr)].to_vec())
            }
        };

        Ok(Cell::new(circ_id, command, body))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curcid_len_default() {
        let circ_id = CircidLen::default();
        assert_eq!(circ_id, CircidLen::MODERN(0));
    }

    #[test]
    fn test_cell_body_default() {
        let body = CellBody::default();
        assert_eq!(body, CellBody::Fixed([0; CELL_BODY_LEN]));
    }
    
    #[test]
    fn test_cell_command_tor_serializer_1() {
        let command = CellCommand::CREATE;
        let bytes = command.to_bytes();
        let new_command = CellCommand::from_bytes(&bytes, 0).unwrap();
        assert_eq!(command, new_command);
    }

    #[test]
    fn test_cell_command_tor_serializer_2() {
        let command = CellCommand::VERSIONS;
        let bytes = command.to_bytes();
        let new_command = CellCommand::from_bytes(&bytes, 0).unwrap();
        assert_eq!(command, new_command);
    }

    #[test]
    fn test_cell_new() {
        let circ_id = CircidLen::MODERN(1);
        let command = CellCommand::CREATE;
        let body = CellBody::Fixed([1; CELL_BODY_LEN]);
        let cell = Cell::new(circ_id.clone(), command.clone(), body.clone());
        assert_eq!(&cell.circ_id, &circ_id);
        assert_eq!(&cell.command, &command);
        assert_eq!(cell.body, body);
    }

    #[test]
    fn test_cell_tor_serializer_legacy() {
        let circ_id = CircidLen::LEGACY(1);
        let command = CellCommand::CREATE;
        let body = CellBody::Fixed([1; CELL_BODY_LEN]);

        let cell = Cell::new(circ_id.clone(), command.clone(), body.clone());
        let bytes = cell.to_bytes();
        let new_cell = Cell::from_bytes(&bytes, 1).unwrap();
        
        assert_eq!(cell, new_cell);
    }
}