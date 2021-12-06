# letterman_dns

these are dns functions for letterman smtp server and client, it curretly provides async spf validation with tokio.
   
## sample code  

```rust 

use letterman_dns::{SpfConfig,spf};

#[tokio::main]
async fn main() {

    let config:SpfConfig;
    match SpfConfig::new(){
        Ok(v)=>{config = v;},
        Err(_)=>{
            return;
        }
    }

    if true{
        match spf::check(
            &config,
            IpAddr::V4(Ipv4Addr::new(209,85,215,172)),
            // IpAddr::V6(Ipv6Addr::new(2404,6800,4000,0000,0001,0000,0000,0000)),
            // IpAddr::V6(Ipv6Addr::new(2607,f8b0,4fff,ffff,ffff,ffff,ffff,ffff)),
            &String::from("mail-pg1-f172.google.com"), 
            &String::from("gmail.com")
        ).await{
            Ok(_)=>{},
            Err(_)=>{}
        }
    }

}

```
