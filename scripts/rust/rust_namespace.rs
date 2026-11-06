struct Point {
    bar: i32,
    foo: i32,
}

fn scope_probe() {
    let point = Point { bar: 10, foo: 20 };
    std::thread::sleep(std::time::Duration::from_secs(60));
    println!("bar = {}, foo = {}", point.bar, point.foo);
}

fn main() {
    scope_probe();
}
