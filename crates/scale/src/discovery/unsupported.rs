use std::convert::Infallible;
use std::io;
use std::time::Duration;

use crate::discovery::{Advertisement, AdvertisementSource, ScanMode};

pub(super) struct NativeAdvertisements(Infallible);

impl NativeAdvertisements {
    pub(super) fn start(_: ScanMode) -> io::Result<Self> {
        Err(crate::bluetooth_unavailable())
    }
}

impl AdvertisementSource for NativeAdvertisements {
    fn next_advertisement(&mut self, _: Duration) -> io::Result<Option<Advertisement>> {
        match self.0 {}
    }

    fn stop(self) -> io::Result<()> {
        match self.0 {}
    }
}
