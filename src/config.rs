use regex::Regex;
use trust_dns_resolver::config::{ResolverConfig,ResolverOpts};
use trust_dns_resolver::{AsyncResolver};
use trust_dns_resolver::{TokioConnection,TokioConnectionProvider};

///this is a config for validate function currently no user defined parameters are needed in future custom resolvers will be allowed to be passed in config.
/// 
/// ```
/// use tokio_spf_validator::{SpfConfig,validate};
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
/// }
/// ```
pub struct SpfConfig{
    pub resolver:AsyncResolver<TokioConnection,TokioConnectionProvider>,
    pub spf_regex:Regex,
    pub spf_ipv4_regex:Regex,
    pub spf_ipv6_regex:Regex,
    pub spf_domain_regex:Regex,
    pub spf_include_regex:Regex,
    pub spf_redirect_regex:Regex,
    pub spf_mx_regex:Regex,
}

pub struct SpfLookup{
    pub ipv4s:Vec<String>,
    pub ipv6s:Vec<String>,
    pub domains:Vec<String>,
    pub redirects:Vec<String>,
    pub all:bool,
    pub mx:bool
}

// struct 

impl SpfConfig{
    pub fn new()->Result<SpfConfig,&'static str>{

        let resolver;
        match AsyncResolver::tokio(ResolverConfig::default(),ResolverOpts::default()){
            Ok(v)=>{resolver = v;},
            Err(_)=>{
                return Err("failed-init-resolver");
            }
        }

        let spf_regex:Regex;
        match Regex::new(r"v=spf1\s*([\w\d\D]+)"){
            Ok(v)=>{spf_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_regex");}
        }

        let spf_ipv4_regex:Regex;
        match Regex::new(r#"ip4:([\d./]+)"#){
            Ok(v)=>{spf_ipv4_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_ipv4_regex");}
        }

        let spf_ipv6_regex:Regex;
        match Regex::new(r#"ip6:([\w\d:/]+)"#){
            Ok(v)=>{spf_ipv6_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_ipv6_regex");}
        }

        let spf_include_regex:Regex;
        match Regex::new(r"include:([\w\d.-]+)"){
            Ok(v)=>{spf_include_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_include_regex");}
        }

        let spf_domain_regex:Regex;
        match Regex::new(r"a:([\w\d.-]+)"){
            Ok(v)=>{spf_domain_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_includes_regex");}
        }

        let spf_mx_regex:Regex;
        match Regex::new(r"([\d]*)\s*([\w\d.-]+)"){
            Ok(v)=>{spf_mx_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_mx_regex");}
        }

        let spf_redirect_regex:Regex;
        match Regex::new(r"redirect=([\w\d.-]+)"){
            Ok(v)=>{spf_redirect_regex = v;},
            Err(_)=>{return Err("failed-regex-spf_redirect_regex");}
        }

        return Ok(SpfConfig{
            resolver:resolver,
            spf_regex:spf_regex,
            spf_ipv4_regex:spf_ipv4_regex,
            spf_ipv6_regex:spf_ipv6_regex,
            spf_domain_regex:spf_domain_regex,
            spf_include_regex:spf_include_regex,
            spf_redirect_regex:spf_redirect_regex,
            spf_mx_regex:spf_mx_regex
        });

    }
    pub fn build(&self,dns_record:String)->Result<SpfLookup,&'static str>{

        let spf_value:String;
        match self.spf_regex.captures(&dns_record){
            Some(captures)=>{
                match captures.get(1){
                    Some(value)=>{
                        spf_value = value.as_str().to_string();
                    },
                    None=>{
                        return Err("not_spf-string"); 
                    }
                }
            },
            None=>{
                return Err("not_spf");
            }
        }

        // expand_ipv6("2001:4860:4000::/36".to_string());

        // spf_value = "ip4:34.243.61.237 ip4:34.243.61.236 ip6:2a05:d018:e3:8c00:bb71:dea8:8b83:851e 
        // ip6:2a05:d018:e3:8c00:bb71:dea8:8b83:8515
        // include:thirdpartydomain.com include:kingship.com redirect=_spf.google.com redirect=_spf1.google.com -all".to_string();

        let mut ipv4s:Vec<String> = vec![];
        for matched in self.spf_ipv4_regex.captures_iter(&spf_value){
            match matched.get(1){
                Some(v)=>{
                    // ipv4s.append(&mut expand_ipv4(v.as_str().to_string()));
                    ipv4s.push(v.as_str().to_string());
                },
                None=>{}
            }
        }

        let mut ipv6s:Vec<String> = vec![];
        for matched in self.spf_ipv6_regex.captures_iter(&spf_value){
            match matched.get(1){
                Some(v)=>{
                    // ipv6s.append(&mut expand_ipv6(v.as_str().to_string()));
                    ipv6s.push(v.as_str().to_string());
                },
                None=>{}
            }
        }

        let mut domains:Vec<String> = vec![];
        for matched in self.spf_domain_regex.captures_iter(&spf_value){
            match matched.get(1){
                Some(v)=>{
                    domains.push(v.as_str().to_string());
                },
                None=>{}
            }
        }

        let mut redirects:Vec<String> = vec![];
        for matched in self.spf_redirect_regex.captures_iter(&spf_value){
            match matched.get(1){
                Some(v)=>{
                    redirects.push(v.as_str().to_string());
                },
                None=>{}
            }
        }
        for matched in self.spf_include_regex.captures_iter(&spf_value){
            match matched.get(1){
                Some(v)=>{
                    redirects.push(v.as_str().to_string());
                },
                None=>{}
            }
        }

        let mut all:bool = false;
        if dns_record.contains("+all"){
            all = true;
        }

        let mut mx:bool = false;
        if dns_record.contains("mx") || dns_record.contains("MX") || dns_record.contains("Mx"){
            mx = true;
        }

        return Ok(SpfLookup{
            ipv4s:ipv4s,
            ipv6s:ipv6s,
            domains:domains,
            redirects:redirects,
            all:all,
            mx:mx
        });

    }
}