

use crate::SpfConfig;

pub async fn lookup_spf(
    config:&SpfConfig,
    domain:String
)->Result<Vec<String>,&'static str>{

    match lookup_txt(config, domain).await{
        Ok(pool)=>{
            let mut collect = vec![];
            for i in pool{
                if i.contains("spf"){
                    collect.push(i);
                }
            }
            return Ok(collect);
        },
        Err(_)=>{
            return Err("failed-init-lookup");
        }
    }

}

pub async fn lookup_txt(
    config:&SpfConfig,
    domain:String
)->Result<Vec<String>,&'static str>{

    match config.resolver.txt_lookup(domain).await{
        Ok(lookup)=>{
            let mut collect = vec![];
            for a in lookup.iter(){
                collect.push(a.to_string());
            }
            return Ok(collect);
        },
        Err(_)=>{return Err("failed-init-lookup");}
    }

}

pub async fn lookup_mx(
    config:&SpfConfig,
    domain:String
)->Result<Vec<String>,&'static str>{

    match config.resolver.mx_lookup(domain).await{
        Ok(lookup)=>{
            let mut collect = vec![];
            for a in lookup.iter(){
                match config.spf_mx_regex.captures(&a.to_string()){
                    Some(captures)=>{
                        match captures.get(2){
                            Some(v)=>{
                                let mut process = v.as_str().to_string();
                                process.pop();
                                collect.push(process);
                            },
                            None=>{}
                        }
                    },
                    None=>{}
                }
            }
            return Ok(collect);
        },
        Err(_)=>{return Err("failed-init-lookup");}
    }

}