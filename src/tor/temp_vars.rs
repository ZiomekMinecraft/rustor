use std::time::{Instant, Duration};

#[derive(Debug, Clone)]
pub struct ValueExpiredError;

impl std::fmt::Display for ValueExpiredError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Value expired")
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct TempVars<T> {
    temp_var: T,
    created_at: Instant,
    lifetime: Duration,
}

impl <T> TempVars<T> {
    pub fn new(temp_var: T, lifetime: Duration) -> Self {
        TempVars {
            temp_var,
            created_at: Instant::now(),
            lifetime,
        }
    }

    pub fn get(&self) -> Result<&T, ValueExpiredError> {

        if self.is_expired() {
            return Err(ValueExpiredError);
        }

        Ok(&self.temp_var)
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.lifetime
    }
    
}
