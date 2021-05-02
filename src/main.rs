use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
    env
};
use std::collections::HashMap;
use uuid::Uuid;

fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("file not found");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l|l.expect("Could not parse file"))
        .collect()
}

fn main() {
    let mut cpe_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut vuln_map: HashMap<String, Vec<String>> = HashMap::new();

    let args: Vec<String> = env::args().collect();
    let filename = &args[1];

    let lines = lines_from_file(filename);

    let mut main_file = File::create("elem-list.csv").expect("Failed to create elem file");
    let mut cpe_file = File::create("cpe-list.csv").expect("Failed to create cpe file");
    let mut vuln_file = File::create("vuln-list.csv").expect("Failed to create vuln file");

    for line in lines {
        let my_uuid = Uuid::new_v4();

        let res: Vec<String> = line.split(",").map(|s| s.to_string()).collect();

        let id = my_uuid.to_string();

        // elements
        let elem = &res[0];
        let res_string : String = format!("{0},{1}\n", id, elem);
        main_file.write_all(res_string.as_bytes()).expect("Failed to write to elem file");

        // cpes
        let cpes = &res[1];
        let cpe_list: Vec<String> = cpes.split("|").map(|s| s.to_string()).collect();
        cpe_map.insert(id.to_string(), cpe_list);

        // vulns
        let vulns = &res[2];
        let vuln_list: Vec<String> = vulns.split("|").map(|s| s.to_string()).collect();
        vuln_map.insert(id.to_string(), vuln_list);

        // CPEs
        for(key, value) in &cpe_map {
            let v1_iter = value.iter();
            for val in v1_iter {
                if(!val.is_empty()) {
                    let res_string : String = format!("{0},{1}\n", key, val);
                    cpe_file.write_all(res_string.as_bytes()).expect("Failed to write to CPE file");
                }
            }
        }

        // Vulns
        for(key, value) in &vuln_map {
            let v1_iter = value.iter();
            for val in v1_iter {
                if(!val.is_empty()) {
                    let res_string : String = format!("{0},{1}\n", key, val);
                    vuln_file.write_all(res_string.as_bytes()).expect("Failed to write to Vuln file");
                }
            }
        }


    }
    
    

}
