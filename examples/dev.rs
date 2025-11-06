use std::str::FromStr;

use ashura::types::crypt::tpm2::Tpm2Crypt;
use tss_esapi::{tcti_ldr::{DeviceConfig, TabrmdConfig}, TctiNameConf};
// this example is simply a dev sandbox test for testing out code snippets
fn main() {
    // let tcti = TctiNameConf::from_environment_variable()
    //     .unwrap_or_else(|_| TctiNameConf::Tabrmd(TabrmdConfig::default()));
    // 
    let tcti = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0").unwrap());
    let tpm2_crypt = Tpm2Crypt::new(&tcti);
    println!("{:#?}", tpm2_crypt);
    
    tpm2_crypt.gen_srk();
}
