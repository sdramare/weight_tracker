use std::io;

#[cfg(any(windows, test))]
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
#[cfg(any(windows, test))]
use serde_json::{Map, Value};

#[cfg(any(windows, test))]
use super::{EuropeSession, integer_text};
#[cfg(any(windows, test))]
use crate::BluetoothAddress;

#[cfg(any(windows, test))]
const S200_MS113_MODEL: &str = "xiaomi.scales.ms113";
#[cfg(any(windows, test))]
const ALLOCATE_DEVICE_ID_PATH: &str = "/device/bltapplydid";
#[cfg(any(windows, test))]
const STANDARD_BIND_PATH: &str = "/v2/device/ble_standard_bind";
#[cfg(any(windows, test))]
const DEVICE_LIST_PATH: &str = "/v2/home/device_list_page";

pub(crate) struct CloudDeviceId(String);

impl std::fmt::Display for CloudDeviceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl CloudDeviceId {
    #[cfg(any(windows, test))]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(any(windows, test))]
    fn from_reply(result: &Value) -> io::Result<Self> {
        let value = result
            .as_str()
            .or_else(|| result.get("did")?.as_str())
            .ok_or_else(|| invalid_reply("Xiaomi did not return a BLE device ID"))?;
        Self::parse(value).ok_or_else(|| invalid_reply("Xiaomi returned an invalid BLE device ID"))
    }

    pub(crate) fn from_scale_field(field: &[u8]) -> io::Result<Option<Self>> {
        let invalid_id = || invalid_reply("The scale reported an invalid stored Xiaomi device ID.");
        let value = std::str::from_utf8(field)
            .map_err(|_| invalid_id())?
            .trim_start_matches('\0');
        if value.is_empty() {
            return Ok(None);
        }
        Self::parse(value).map(Some).ok_or_else(invalid_id)
    }

    fn parse(value: &str) -> Option<Self> {
        (!value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
        .then(|| Self(value.to_owned()))
    }
}

#[cfg(any(windows, test))]
pub(crate) struct CloudAuthorization {
    pub(crate) certificate: Vec<u8>,
    pub(crate) signature: [u8; 64],
    pub(crate) utc: u32,
}

#[cfg(any(windows, test))]
impl CloudAuthorization {
    fn from_reply(result: &Value) -> io::Result<Self> {
        let reply = result
            .as_object()
            .ok_or_else(|| invalid_reply("Xiaomi returned an invalid registration response"))?;
        if reply.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(io::Error::other(
                "Xiaomi declined to authorize BLE registration",
            ));
        }
        let certificate = authorization_bytes(reply, "cloud_cert")?;
        if certificate.first() != Some(&0x30) || certificate.len() > 4096 {
            return Err(invalid_reply(
                "Xiaomi returned an invalid registration certificate",
            ));
        }
        let signature = authorization_bytes(reply, "cloud_sign")?
            .try_into()
            .map_err(|_| {
                invalid_reply("Xiaomi returned a registration signature of the wrong length")
            })?;
        let utc = reply
            .get("utc")
            .and_then(|value| match value {
                Value::String(text) => text.parse().ok(),
                Value::Number(value) => integer_text(value)?.parse().ok(),
                _ => None,
            })
            .filter(|utc| *utc != 0)
            .ok_or_else(|| invalid_reply("Xiaomi returned an invalid registration timestamp"))?;
        Ok(Self {
            certificate,
            signature,
            utc,
        })
    }
}

#[cfg(any(windows, test))]
impl EuropeSession {
    pub(crate) fn allocate_device_id(
        &self,
        address: BluetoothAddress,
        login_token_hex: &str,
        stored_device_id: Option<&CloudDeviceId>,
    ) -> io::Result<CloudDeviceId> {
        let data = device_id_request(address, login_token_hex, stored_device_id);
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
            device_id = device_id,
            token = login_token_hex,
            key = bind_key_hex,
        );
        let reply = self.request(STANDARD_BIND_PATH, &data)?;
        CloudAuthorization::from_reply(&reply)
    }

    pub(crate) fn lists_device(&self, device_id: &CloudDeviceId) -> io::Result<bool> {
        let data = format!(
            r#"{{"limit":200,"get_split_device":true,"get_third_device":true,"dids":["{device_id}"]}}"#,
            device_id = device_id,
        );
        let result = self.request(DEVICE_LIST_PATH, &data)?;
        device_list_contains(&result, device_id)
    }
}

#[cfg(any(windows, test))]
fn device_id_request(
    address: BluetoothAddress,
    login_token_hex: &str,
    stored_device_id: Option<&CloudDeviceId>,
) -> String {
    // Xiaomi Home includes the old DID in this request when the scale supplies one.
    let stored_field = stored_device_id
        .map(|id| format!(r#","did":"{id}""#))
        .unwrap_or_default();
    format!(
        r#"{{"mac":"{address}","model":"{S200_MS113_MODEL}","token":"{login_token_hex}"{stored_field}}}"#,
    )
}

#[cfg(any(windows, test))]
fn device_list_contains(result: &Value, device_id: &CloudDeviceId) -> io::Result<bool> {
    let result = result
        .as_object()
        .ok_or_else(|| invalid_reply("Xiaomi returned an invalid device list"))?;
    let entries = result
        .get("list")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_reply("Xiaomi did not return a device list"))?;
    for entry in entries {
        let id = entry
            .get("did")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_reply("Xiaomi returned an entry without a device ID"))?;
        if id == device_id.as_str() {
            return Ok(true);
        }
    }
    if result.get("has_more").and_then(Value::as_bool) == Some(true) {
        return Err(invalid_reply("Xiaomi returned an incomplete device list"));
    }
    Ok(false)
}

#[cfg(any(windows, test))]
fn authorization_bytes(reply: &Map<String, Value>, key: &str) -> io::Result<Vec<u8>> {
    let value = reply
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_reply("Xiaomi omitted registration authorization data"))?;
    Base64Url::decode_vec(value)
        .or_else(|_| Base64UrlUnpadded::decode_vec(value))
        .or_else(|_| Base64::decode_vec(value))
        .or_else(|_| Base64Unpadded::decode_vec(value))
        .map_err(|_| invalid_reply("Xiaomi returned invalid registration authorization data"))
}

fn invalid_reply(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde_json::{from_str, json};

    use super::{CloudAuthorization, CloudDeviceId, device_id_request, device_list_contains};
    use crate::BluetoothAddress;

    #[test]
    fn parses_the_device_id_and_authorization_from_xiaomi() {
        let did = json!("blt.3.test-dev");
        assert_eq!(
            CloudDeviceId::from_reply(&did).unwrap().as_str(),
            "blt.3.test-dev"
        );
        let cert = Base64UrlUnpadded::encode_string(&[0x30, 0x01, 0xfb]);
        let signature = Base64UrlUnpadded::encode_string(&[0xe1; 64]);
        let reply =
            json!({"success":true,"cloud_cert":cert,"cloud_sign":signature,"utc":1795700991.0});
        let grant = CloudAuthorization::from_reply(&reply).unwrap();
        assert_eq!(grant.certificate, [0x30, 0x01, 0xfb]);
        assert_eq!(grant.signature, [0xe1; 64]);
        assert_eq!(grant.utc, 1795700991);
        let denied = json!({"success":false});
        assert!(CloudAuthorization::from_reply(&denied).is_err());
    }

    #[test]
    fn checks_the_exact_stored_device_id_in_a_complete_cloud_list() {
        let stored = CloudDeviceId::parse("blt.4.example000000").unwrap();
        let fixtures = [
            (r#"{"list":[{"did":"blt.4.example000000"}]}"#, Some(true)),
            (r#"{"list":[{"did":"blt.4.example000001"}]}"#, Some(false)),
            (r#"{"list":[],"has_more":true}"#, None),
            (r#"{}"#, None),
        ];
        for (json, expected) in fixtures {
            let result = from_str(json).unwrap();
            assert_eq!(device_list_contains(&result, &stored).ok(), expected);
        }
    }

    #[test]
    fn allocates_the_fresh_token_with_the_stored_id_when_present() {
        let address = BluetoothAddress(1);
        let stored = CloudDeviceId::parse("blt.4.example000000").unwrap();
        assert_eq!(
            device_id_request(address, "test-token", None),
            r#"{"mac":"00:00:00:00:00:01","model":"xiaomi.scales.ms113","token":"test-token"}"#,
        );
        assert_eq!(
            device_id_request(address, "test-token", Some(&stored)),
            r#"{"mac":"00:00:00:00:00:01","model":"xiaomi.scales.ms113","token":"test-token","did":"blt.4.example000000"}"#,
        );
    }
}
