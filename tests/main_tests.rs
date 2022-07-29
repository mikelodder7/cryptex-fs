use cryptex::KeyRing;
use cryptex_fs::KeyRingFileOpenOptions;

#[test]
fn test() {
    let options = KeyRingFileOpenOptions::with_default_password_hash("cryptex-fs-password");
    let res = options.open_keyring();
    assert!(res.is_ok());
    let mut keyring = res.unwrap();
    let res = keyring.set_secret("test_key", b"test_value");
    assert!(res.is_ok());
    let res = keyring.get_secret("test_key");
    assert!(res.is_ok());
    let test_value = res.unwrap();
    assert_eq!(test_value.as_slice(), b"test_value");
    let res = keyring.delete_secret("test_key");
    assert!(res.is_ok());
}