use std::io;

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use windows::Data::Json::{JsonObject, JsonValue};
use windows::core::HSTRING;

use super::EuropeSession;
use crate::BluetoothAddress;

const S200_MS113_MODEL: &str = "xiaomi.scales.ms113";
const ALLOCATE_DEVICE_ID_PATH: &str = "/device/bltapplydid";
const STANDARD_BIND_PATH: &str = "/v2/device/ble_standard_bind";

pub(crate) struct CloudDeviceId(String);

impl CloudDeviceId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn from_reply(result: &JsonValue) -> io::Result<Self> {
        let value = result
            .GetString()
            .or_else(|_| result.GetObject()?.GetNamedString(&HSTRING::from("did")))
            .map_err(|_| invalid_reply("Xiaomi did not return a BLE device ID"))?
            .to_string_lossy();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(invalid_reply("Xiaomi returned an invalid BLE device ID"));
        }
        Ok(Self(value))
    }
}

pub(crate) struct CloudAuthorization {
    pub(crate) certificate: Vec<u8>,
    pub(crate) signature: [u8; 64],
    pub(crate) utc: u32,
}

impl CloudAuthorization {
    fn from_reply(result: &JsonValue) -> io::Result<Self> {
        let reply = result
            .GetObject()
            .map_err(|_| invalid_reply("Xiaomi returned an invalid registration response"))?;
        if !reply
            .GetNamedBoolean(&HSTRING::from("success"))
            .unwrap_or(false)
        {
            return Err(io::Error::other(
                "Xiaomi declined to authorize BLE registration",
            ));
        }
        let certificate = authorization_bytes(&reply, "cloud_cert")?;
        if certificate.first() != Some(&0x30) || certificate.len() > 4096 {
            return Err(invalid_reply(
                "Xiaomi returned an invalid registration certificate",
            ));
        }
        let signature = authorization_bytes(&reply, "cloud_sign")?
            .try_into()
            .map_err(|_| {
                invalid_reply("Xiaomi returned a registration signature of the wrong length")
            })?;
        let utc_field = HSTRING::from("utc");
        let utc = reply
            .GetNamedString(&utc_field)
            .or_else(|_| reply.GetNamedValue(&utc_field)?.Stringify())
            .ok()
            .and_then(|value| value.to_string_lossy().parse().ok())
            .filter(|utc| *utc != 0)
            .ok_or_else(|| invalid_reply("Xiaomi returned an invalid registration timestamp"))?;
        Ok(Self {
            certificate,
            signature,
            utc,
        })
    }
}

impl EuropeSession {
    pub(crate) fn allocate_device_id(
        &self,
        address: BluetoothAddress,
        login_token_hex: &str,
    ) -> io::Result<CloudDeviceId> {
        let data = format!(
            r#"{{"mac":"{address}","model":"{S200_MS113_MODEL}","token":"{login_token_hex}"}}"#
        );
        let reply = self.request(ALLOCATE_DEVICE_ID_PATH, &data)?;
        CloudDeviceId::from_reply(&reply)
    }

    pub(crate) fn authorize_standard_registration(
        &self,
        device_id: &CloudDeviceId,
        login_token_hex: &str,
        bind_key_hex: &str,
    ) -> io::Result<CloudAuthorization> {
        // This ms113 profile provides no secondary MAC. Xiaomi Home sends an empty smac in that case.
        let data = format!(
            concat!(
                r#"{{"did":"{device_id}","token":"{token}","props":["#,
                r#"{{"type":"prop","key":"bind_key","value":"{key}"}},"#,
                r#"{{"type":"prop","key":"smac","value":""}}],"beacon_key":"{key}"}}"#,
            ),
            device_id = device_id.as_str(),
            token = login_token_hex,
            key = bind_key_hex,
        );
        let reply = self.request(STANDARD_BIND_PATH, &data)?;
        CloudAuthorization::from_reply(&reply)
    }
}

fn authorization_bytes(reply: &JsonObject, key: &str) -> io::Result<Vec<u8>> {
    let value = reply
        .GetNamedString(&HSTRING::from(key))
        .map_err(|_| invalid_reply("Xiaomi omitted registration authorization data"))?
        .to_string_lossy();
    Base64Url::decode_vec(&value)
        .or_else(|_| Base64UrlUnpadded::decode_vec(&value))
        .or_else(|_| Base64::decode_vec(&value))
        .or_else(|_| Base64Unpadded::decode_vec(&value))
        .map_err(|_| invalid_reply("Xiaomi returned invalid registration authorization data"))
}

fn invalid_reply(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use windows::Data::Json::JsonValue;
    use windows::core::HSTRING;

    use super::{CloudAuthorization, CloudDeviceId};
    use crate::Apartment;

    #[test]
    fn parses_the_device_id_and_authorization_from_xiaomi() {
        let _apartment = Apartment::initialize().unwrap();
        let did = JsonValue::Parse(&HSTRING::from(r#""blt.3.test-dev""#)).unwrap();
        assert_eq!(
            CloudDeviceId::from_reply(&did).unwrap().as_str(),
            "blt.3.test-dev"
        );
        let cert = Base64UrlUnpadded::encode_string(&[0x30, 0x01, 0xfb]);
        let signature = Base64UrlUnpadded::encode_string(&[0xe1; 64]);
        let reply = JsonValue::Parse(&HSTRING::from(format!(
            r#"{{"success":true,"cloud_cert":"{cert}","cloud_sign":"{signature}","utc":1795700991}}"#
        ))).unwrap();
        let grant = CloudAuthorization::from_reply(&reply).unwrap();
        assert_eq!(grant.certificate, [0x30, 0x01, 0xfb]);
        assert_eq!(grant.signature, [0xe1; 64]);
        assert_eq!(grant.utc, 1795700991);
        let denied = JsonValue::Parse(&HSTRING::from(r#"{"success":false}"#)).unwrap();
        assert!(CloudAuthorization::from_reply(&denied).is_err());
    }
}
