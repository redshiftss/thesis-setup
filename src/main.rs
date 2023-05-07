extern crate rs_docker;

use std::{sync::{Mutex, Arc}, thread::{scope, self}, time::{self, UNIX_EPOCH, Duration}, fs::{self, File}, io::Write};
use std::process::Command;
use std::time::SystemTime;

fn main() {
    run_pipeline(1);
}

fn run_pipeline(pagenum: u32){
    cleanup();
    let imgs = aggregate_and_pull_images(pagenum);
    aggregate_ports();
    run_nuclei(pagenum);
    run_trivy(pagenum, imgs);
}

#[derive(Debug)]
struct MyImage {
    name : String,
    ips : Vec<String>
}

struct Vulnerability {
    severity : String,
    cvenum : String,
}

struct ImageReport {
    image_name : String,
    vuln_list_static : Vec<Vulnerability>,
    vuln_list_dynamic : Vec<Vulnerability>
}

fn run_trivy(pagenum : u32, images : Vec<MyImage>) {
    let mut res = String::new();
    println!("{:?}", images);

    for image in images {
        let output = Command::new("bash")
                .arg("-c")
                .arg(format!("trivy image -f json {}", image.name))
                .output()
                .expect("failed to execute trivy");
        let h = format!("{},\n\n", String::from_utf8(output.stdout).unwrap());
        res.push_str(&h);
    }

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let filename = format!("trivy/results_{:?}_{}.json", since_the_epoch, pagenum);

    let mut file = File::create(filename).unwrap();
    file.write_all(res.as_bytes()).unwrap();
}

fn aggregate_and_pull_images(pagenum: u32) -> Vec<MyImage> {
    let body: serde_json::Value = ureq::get(&format!("https://hub.docker.com/api/content/v1/products/search?page={}&page_size=5&q=", pagenum))
    .set("Search-Version", "v3")
    .call()
    .unwrap()
    .into_json()
    .unwrap();

    let mut res = Vec::new();

    for v in body["summaries"].as_array().unwrap() {
        res.push(format!("{}", v["name"].as_str().unwrap().clone()))
    }

    for image in res {
        Command::new("bash")
        .arg("-c")
        .arg(format!("docker pull {}", image))
        .output()
        .expect("failed to pull image");

        let output = Command::new("bash")
        .arg("-c")
        .arg(format!("docker run -d -P {}", image))
        .output()
        .expect("failed to run image");

        // let h = String::from_utf8(output.stdout).unwrap();
        // println!("{}", h);
        println!("finished pulling images...");
    }

    thread::sleep(Duration::from_secs(1));

    let output = Command::new("bash")
    .arg("-c") 
    .arg("docker ps --format \"{{.Image}} {{.Ports}}\" | awk -F \'->\' \'{print $1}\'")
    .output()
    .expect("failed to aggregate ports");

    let mut imgs = Vec::new();
        
    let str = String::from_utf8(output.stdout).unwrap();
    
    let lines = str.split("\n");

    for line in lines {
        let tokens = line.split(" ").collect::<Vec<&str>>();
        let name = tokens[0];
        let mut ips = Vec::new();
        let mut i = 1;

        while i < tokens.len() {
            ips.push(tokens[i].to_string());
            i+=1;
        }
        if (name != ""){
            imgs.push(MyImage { name: name.to_string(), ips: ips })
        }
    }
    return imgs;
}

fn aggregate_ports(){
    Command::new("bash")
    .arg("-c") 
    .arg("docker ps --format \"{{.Ports}}\" | awk -F \'->\' \'{print $1}\' > ports.txt")
    .output()
    .expect("failed to aggregate ports");
    println!("wrote ports to file...")
}

fn run_nuclei(pagenum: u32){
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let filename = format!("nuclei/results_{:?}_{}.json", since_the_epoch, pagenum);
    println!("filename: {}", filename);
    Command::new("bash")
    .arg("-c")
    .arg(format!("~/go/bin/nuclei -l ports.txt -hm -ni -je {}", filename))
    .status()
    .expect("failed to run nuclei");
}

fn cleanup() {
    Command::new("bash")
    .arg("-c")
    .arg("docker stop $(docker ps -a -q)")
    .status()
    .expect("failed to run nuclei");
    Command::new("bash")
    .arg("-c")
    .arg("docker rm $(docker ps -a -q)")
    .status()
    .expect("failed to run nuclei");
}