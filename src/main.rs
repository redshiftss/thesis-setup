extern crate rs_docker;

use std::{sync::{Mutex, Arc}, thread::scope};
use std::process::Command;
use rs_docker::{Docker, image::Image};
use ureq::{Agent, AgentBuilder};
use chrono::{DateTime,  Utc};
fn main() {
    let mut docker = match Docker::connect("unix:///var/run/docker.sock") {
    	Ok(docker) => docker,
        Err(e) => { panic!("{}", e); }
    };

    // let images = match docker.get_images(true) {
    //     Ok(images) => images,
    //     Err(e) => { panic!("{}", e); }
    // };

    run_pipeline(1);
    run_pipeline(2);
    run_pipeline(3);
    run_pipeline(4);

    // let cores = 10;
    // let image_queue = Arc::new(Mutex::new(images));
    // scope(|s| {
    //     for _ in 0..cores {
    //         let cqc = image_queue.clone();
    //         s.spawn(move ||{
    //             while let Some(image) = {
    //                 let mut guard = cqc.lock().unwrap();
    //                 let container = guard.pop();
    //                 drop(guard);
    //                 container
    //             } {
    //                 // analyze_image(image);
    //             }
    //         });
    //     }
    // });
}

fn run_pipeline(pagenum: u32){
    aggregate_and_pull_images(pagenum);
    aggregate_ports();
    run_nuclei();
    cleanup();
}

fn analyze_image(selected: Image) {
    let output = Command::new("bash")
        .arg("-c")
        .arg(format!("trivy image -f json {}", selected.RepoTags[0]))
        .output()
        .expect("failed to execute trivy");
    let h = String::from_utf8(output.stdout).unwrap();
    println!("{}", h);
}

fn aggregate_and_pull_images(pagenum: u32) {
    let body: serde_json::Value = ureq::get(&format!("https://hub.docker.com/api/content/v1/products/search?page={}&page_size=25&q=", pagenum))
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
        println!("finished pulling images...")
    }

}

fn aggregate_ports(){
    Command::new("bash")
    .arg("-c")
    .arg("docker ps --format \"{{.Ports}}\" | awk -F \'->\' \'{print $1}\' > ports.txt")
    .output()
    .expect("failed to aggregate ports");
    println!("wrote ports to file...")
}

fn run_nuclei(){
    let filename = format!("results_{}.json", Utc::now());
    println!("filename: {}", filename);
    Command::new("bash")
    .arg("-c")
    .arg(format!("~/go/bin/nuclei -l ports.txt  -ni -je {}", filename))
    .status()
    .expect("failed to run nuclei");

    // let h = String::from_utf8(output.stdout).unwrap();
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