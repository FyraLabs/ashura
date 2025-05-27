use tss_esapi::{TctiNameConf, Context};



pub fn new_ctx() -> Context {
    Context::new(TctiNameConf::from_environment_variable().unwrap_or(TctiNameConf::Device(Default::default()))).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ctx() {
        let ctx = new_ctx();
        // assert!(ctx);
    }
}
