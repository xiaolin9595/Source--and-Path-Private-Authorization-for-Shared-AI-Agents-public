use plan_a_sr_joint_bbs::http_bridge::make_trusted_config;
fn main() {
    match make_trusted_config() {
        Ok(c) => println!("{}", serde_json::to_string_pretty(&c).unwrap()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    }
}
