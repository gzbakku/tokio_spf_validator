use std::net::{Ipv4Addr, Ipv6Addr};
use std::net::IpAddr;
use cidr::{Ipv4Cidr,Ipv6Cidr};

use crate::workers::{lookup_spf,lookup_mx};
use crate::{SpfConfig,SpfLookup};

pub enum SpfQueryResult{
    Pass,Fail,SoftFail
}


///this is exported as validate in lib
/// 
/// ```
/// use letterman_dns::{SpfConfig,spf};
/// use std::net::IpAddr;
///
/// #[tokio::main]
/// async fn main() {
///
///     let config:SpfConfig;
///     match SpfConfig::new(){
///         Ok(v)=>{config = v;},
///         Err(_)=>{
///             return;
///         }
///     }
///
///     if true{
///         match spf::check(
///             &config,
///             IpAddr::V4(Ipv4Addr::new(209,85,215,172)),
///             &String::from("mail-pg1-f172.google.com"), 
///             &String::from("gmail.com")
///         ).await{
///             Ok(_)=>{},
///             Err(_)=>{}
///         }
///     }
///
/// }
/// ```
pub async fn check(
    config:&SpfConfig,
    ip:IpAddr,
    host:&String,
    sender:&String
)-> Result<SpfQueryResult,&'static str>{

    let hold_ip = ip.to_string();
    let mut ip_as_ipv4:Ipv4Addr = Ipv4Addr::new(0,0,0,0);
    let mut ip_as_ipv6:Ipv6Addr = Ipv6Addr::new(0,0,0,0,0,0,0,0);
    let mut sender_hold = sender.to_string();
    let mut redirects:Vec<String> = vec![];

    if ip.is_ipv4(){
        match hold_ip.parse::<Ipv4Addr>(){
            Ok(v)=>{
                ip_as_ipv4 = v;
            },
            Err(_)=>{
                return Err("failed-lookup-txt");
            }
        }
    }
    if ip.is_ipv6(){
        match hold_ip.parse::<Ipv6Addr>(){
            Ok(v)=>{
                ip_as_ipv6 = v;
            },
            Err(_)=>{
                return Err("failed-lookup-txt");
            }
        }
    }

    //lookup mx records
    let mx_records:Vec<String>;
    match lookup_mx(config,sender_hold.to_string()).await{
        Ok(v)=>{mx_records = v;},
        Err(_)=>{
            // println!("mx_records lookup failed");
            return Err("failed-lookup-mx_records");
        }
    }

    // println!("mx_records : {:?}",mx_records);

    loop{

        if redirects.len() > 0{
            sender_hold = redirects.remove(0);
        }

        // println!("sender_hold : {:?}",sender_hold);

        //get spf record
        let records:Vec<String>;
        match lookup_spf(config,sender_hold.to_string()).await{
            Ok(v)=>{records = v;},
            Err(_)=>{
                // println!("lookup failed");
                return Err("failed-lookup-txt");
            }
        }

        for record in records{

            let mut lookup:SpfLookup;
            match config.build(record){
                Ok(v)=>{lookup = v;},
                Err(_)=>{
                    // println!("spf build failed");
                    return Err("failed-build-spf");
                }
            }

            for this_ip in lookup.ipv4s{
                if match_ipv4(this_ip,&ip_as_ipv4,&hold_ip){
                    // println!("found ipv4");
                    return Ok(SpfQueryResult::Pass);
                }
            }

            for this_ip in lookup.ipv6s{
                if match_ipv6(this_ip,&ip_as_ipv6,&hold_ip){
                    // println!("found ipv6");
                    return Ok(SpfQueryResult::Pass);
                }
            }

            if lookup.domains.contains(&host){
                // println!("found domain");
                return Ok(SpfQueryResult::Pass);
            }

            if lookup.mx{
                if mx_records.contains(host){
                    // println!("found mx");
                    return Ok(SpfQueryResult::Pass);
                }
            }

            if lookup.redirects.len() == 0{
                if redirects.len() == 0{
                    if lookup.all{
                        // println!("found all");
                        return Ok(SpfQueryResult::SoftFail);
                    } else {
                        // println!("validation failed");
                        return Ok(SpfQueryResult::Fail);
                    }
                }
            } else {
                // println!("found redirect");
                redirects.append(&mut lookup.redirects);
            }

        }

    }

}

fn match_ipv6(ip:String,base:&Ipv6Addr,base_str:&String)->bool{

    if !ip.contains("/"){
        if &ip == base_str{
            return true;
        }
    }

    let hold:Vec<&str> = ip.split("/").collect();
    if hold.len() != 2{
        return false;
    }
    let range:u8;
    match hold[1].parse::<u8>(){
        Ok(v)=>{range = v;},
        Err(_)=>{
            return false;
        }
    }
    let parsed_ip:Ipv6Addr;
    match hold[0].parse(){
        Ok(v)=>{parsed_ip = v;},
        Err(_)=>{
            return false;
        }
    }

    match Ipv6Cidr::new(parsed_ip,range){
        Ok(ips)=>{
            if ips.contains(base){
                return true;
            } else {
                return false;
            }
        },
        Err(_)=>{
            return false;
        }
    }

}

fn match_ipv4(ip:String,base:&Ipv4Addr,base_str:&String)->bool{

    if !ip.contains("/"){
        if &ip == base_str{
            return true;
        }
    }

    let hold:Vec<&str> = ip.split("/").collect();
    if hold.len() != 2{
        return false;
    }
    let range:u8;
    match hold[1].parse::<u8>(){
        Ok(v)=>{range = v;},
        Err(_)=>{
            return false;
        }
    }
    let parsed_ip:Ipv4Addr;
    match hold[0].parse(){
        Ok(v)=>{parsed_ip = v;},
        Err(_)=>{
            return false;
        }
    }

    match Ipv4Cidr::new(parsed_ip,range){
        Ok(ips)=>{
            if ips.contains(base){
                return true;
            } else {
                return false;
            }
        },
        Err(_)=>{
            return false;
        }
    }

}