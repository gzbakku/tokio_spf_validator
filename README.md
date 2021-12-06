# tokio_spf_validator

this is a spf validator for smtp servers, it is based on tokio and use trust_dns_resolver for dns queires with default resolver, currently supported features are mx record validation,softfail,domain validation, ipv4 and ipv6 validation, cidr ipv4 and ipv6 validation and redirect support.

## sample code  

```rust 

use tokio_spf_validator::{SpfConfig,validate};

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
        match validate(
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
