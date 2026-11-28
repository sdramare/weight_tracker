use std::fmt;

/// A scale's Bluetooth device address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BluetoothAddress(pub(super) u64);

impl fmt::Display for BluetoothAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [_, _, a, b, c, d, e, f] = self.0.to_be_bytes();
        write!(formatter, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
    }
}

/// The scale's advertised name or its model name when the advertisement has no name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleName<'a>(pub(super) &'a str);

impl fmt::Display for ScaleName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Received Bluetooth signal strength, measured in dBm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignalStrength(pub(super) i16);

impl fmt::Display for SignalStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} dBm", self.0)
    }
}

/// A weight transmitted by the S200, stored in hundredths of a kilogram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weight(pub(super) u32);

impl Weight {
    pub const fn from_hundredths_of_kg(value: u32) -> Self {
        Self(value)
    }

    pub const fn hundredths_of_kg(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Weight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{:02} kg", self.0 / 100, self.0 % 100)
    }
}

/// The live display value or the final reading reported by the scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightReading {
    Live(Weight),
    Settled(Weight),
}

/// The 128-bit UUID of a Bluetooth GATT service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GattServiceUuid(pub(super) u128);

impl fmt::Display for GattServiceUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g, h, i, j, k, l, m, n, o, p, q] = self.0.to_be_bytes();
        write!(
            f,
            "{a:02X}{b:02X}{c:02X}{d:02X}-{e:02X}{g:02X}-{h:02X}{i:02X}-{j:02X}{k:02X}-{l:02X}{m:02X}{n:02X}{o:02X}{p:02X}{q:02X}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{BluetoothAddress, GattServiceUuid, ScaleName, SignalStrength};

    #[test]
    fn displays_bluetooth_values_in_the_existing_formats() {
        let service = GattServiceUuid(0x0000_fe95_0000_1000_8000_0080_5f9b_34fb);
        assert_eq!(service.to_string(), "0000FE95-0000-1000-8000-00805F9B34FB");
        assert_eq!(
            BluetoothAddress(0x1234_5678_9abc).to_string(),
            "12:34:56:78:9A:BC"
        );
        assert_eq!(SignalStrength(-60).to_string(), "-60 dBm");
        assert_eq!(
            ScaleName("Xiaomi Scale S200").to_string(),
            "Xiaomi Scale S200"
        );
    }
}
