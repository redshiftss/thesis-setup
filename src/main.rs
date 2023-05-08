extern crate rs_docker;

use std::{sync::{Mutex, Arc}, thread::{scope, self}, time::{self, UNIX_EPOCH, Duration}, fs::{self, File, OpenOptions}, io::Write, collections::{HashMap, hash_map::Entry}, ops::Deref, path::Path, };
use std::process::Command;
use std::time::SystemTime;

use rs_docker::image::Image;
use serde_json::Value;

fn main() {
    let mut i = 1;
    while i <= 300 {
        run_pipeline(i);
        i+=1;
    }
}

fn run_pipeline(pagenum: u32){
    cleanup();
    let imgs = aggregate_and_pull_images(pagenum);
    let cp = imgs.clone();
    aggregate_ports();
    let nucleifile = run_nuclei(pagenum);
    let trivyfile = run_trivy(pagenum, imgs);
    let mut res = HashMap::new();
    if Path::new(&nucleifile).exists() {
        aggregate_results_nuclei(res.clone(), cp, nucleifile, pagenum);
        aggregate_results_trivy(res,  trivyfile, pagenum);
    }
}

#[derive(Debug, Clone)]
struct MyImage {
    name : String,
    ips : Vec<String>
}

#[derive(Clone, Debug)]
struct Vulnerability {
    severity : String,
    name : String,
}

#[derive(Clone, Debug)]
struct ImageReport {
    vuln_list_static : Vec<Vulnerability>,
    vuln_list_dynamic : Vec<Vulnerability>
}

fn run_trivy(pagenum : u32, images : Vec<MyImage>) -> String {
    let mut res = String::new();
    println!("{:?}", images);

    for image in images {
        let output = Command::new("bash")
                .arg("-c")
                .arg(format!("trivy image -f json {}", image.name))
                .output()
                .expect("failed to execute trivy");
        let h = format!("{}\n", String::from_utf8(output.stdout).unwrap());
        res.push_str(&h);
    }

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let filename = format!("trivy/results_{:?}_{}.json", since_the_epoch, pagenum);
    let fil = filename.clone();

    let mut file = File::create(filename).unwrap();
    file.write_all(res.as_bytes()).unwrap();
    return fil;
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

fn run_nuclei(pagenum: u32) -> String{
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
    return filename;
}

fn cleanup() {
    Command::new("bash")
    .arg("-c")
    .arg("docker stop $(docker ps -a -q)")
    .status()
    .expect("failed to clean up");
    Command::new("bash")
    .arg("-c")
    .arg("docker rm $(docker ps -a -q)")
    .status()
    .expect("failed to clean up");
    Command::new("bash")
    .arg("-c")
    .arg("docker image prune -a")
    .status()
    .expect("failed to clean up");
}

fn aggregate_results_nuclei(mut results : HashMap<String, ImageReport>, ports : Vec<MyImage>, file : String, pagenum : u32) {
    let nuclei_dump = fs::read_to_string(file).unwrap();
    let json_object : Value = serde_json::from_str(&nuclei_dump).unwrap();
    let json_array = json_object.as_array().unwrap();

    for item in json_array.iter() {
        let vuln = item.as_object().unwrap();
        let hostip = &vuln["host"].to_string().replace("\"", "");
        let severity = &vuln["info"]["severity"];

        let name = &vuln["info"]["name"];

        let mut corresponding_image : String = "".to_string();

        let ip = &hostip.to_string().replace("http://", "");


        for img in ports.clone() {
            if img.ips.contains(ip) {
                // dbg!("a");
                corresponding_image = img.name;
            }
        }

        match results.entry(corresponding_image) {
            Entry::Occupied(mut entry) => {
                let ir = entry.get_mut();
                ir.vuln_list_dynamic.push(Vulnerability { severity: severity.to_string(), name: name.to_string() })
            },
            Entry::Vacant(entry) => {
                let mut dynvec = Vec::new();
                dynvec.push(Vulnerability { severity: severity.to_string(), name: name.to_string()});
                let r = ImageReport{ vuln_list_static: Vec::new(), vuln_list_dynamic: dynvec};
                entry.insert(r);
            }
        }
    }

    for r in results {
        let mut number_of_info = 0;
        let mut number_of_low = 0;
        let mut number_of_medium = 0;
        let mut number_of_high = 0;

        for vuln in  r.1.vuln_list_dynamic {
            match vuln.severity.as_str() {
                "\"info\"" => number_of_info +=1 ,
                "\"low\"" =>  number_of_low +=1,
                "\"medium\"" =>  number_of_medium +=1,
                "\"high\"" =>  number_of_high +=1,
                _ => (),
            }
        }
        if !r.0.is_empty(){
            let r = format!("aggregated dynamic analysis results for image {}: info {}, low {}, medium {}, high {}", r.0, number_of_info, number_of_low, number_of_medium, number_of_high);
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(format!("results_{}.txt", pagenum))
                .unwrap();

            if let Err(e) = writeln!(file, "{}", r) {
                eprintln!("Couldn't write to file: {}", e);
            }
        }
    }
}

fn aggregate_results_trivy(mut results : HashMap<String, ImageReport>, file : String, pagenum : u32) {
    let trivy_dump = fs::read_to_string(file).unwrap();
    let jsons = trivy_dump.trim().split("\n\n").collect::<Vec<_>>();
    for json in jsons {
        let json_object : Value = serde_json::from_str(&json).unwrap();
        if json_object["Results"].as_array().is_none() {
            eprintln!("trivy json malformed: {:?}", &json);
            continue
        }
        let ress  = &json_object["Results"].as_array().unwrap()[0];
        if ress["Vulnerabilities"].as_array().is_none() {
           continue;
        }
        let vulns = ress["Vulnerabilities"].as_array().unwrap();

        let img_name =  &json_object["ArtifactName"].to_string().replace("\"", "");

        for vuln in vulns.iter() {

            let name = &vuln["VulnerabilityID"];
            let severity = &vuln["Severity"];

            match results.entry(img_name.to_string()) {
                Entry::Occupied(mut entry) => {
                    let ir = entry.get_mut();
                    ir.vuln_list_static.push(Vulnerability { severity: severity.to_string(), name: name.to_string() });
                }
                Entry::Vacant(entry) => {
                    let mut statvec = Vec::new();
                    statvec.push(Vulnerability { severity: severity.to_string(), name: name.to_string() });
                    entry.insert(ImageReport { vuln_list_static: statvec, vuln_list_dynamic: Vec::new() });
                }
            }
        }
    }

    dbg!(results.clone());

    for r in results {
        let mut number_of_low = 0;
        let mut number_of_medium = 0;
        let mut number_of_high = 0;

        for vuln in  r.1.vuln_list_static {
            match vuln.severity.as_str() {
                "\"LOW\"" =>  number_of_low +=1,
                "\"MEDIUM\"" =>  number_of_medium +=1,
                "\"HIGH\"" =>  number_of_high +=1,
                _ => (),
            }
        }
        if !r.0.is_empty(){
            let r = format!("aggregated static analysis results for image {} : low {}, medium {}, high {}", r.0, number_of_low, number_of_medium, number_of_high);
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(format!("results_{}.txt", pagenum))
                .unwrap();

            if let Err(e) = writeln!(file, "{}", r) {
                eprintln!("Couldn't write to file: {}", e);
            }
        }
    }
}