pub trait Wipe {
    fn wipe(&mut self);
}

impl Wipe for Vec<u8> {
    fn wipe(&mut self) {
        for byte in self.iter_mut() {
            *byte = 0;
        }
        self.clear();
        self.shrink_to_fit();
    }
}
