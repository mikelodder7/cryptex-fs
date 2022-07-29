use cryptex::KeyRing;
use cryptex_fs::KeyRingFileOpenOptions;

#[test]
fn test() {
    let mut options = KeyRingFileOpenOptions::with_default_password_hash("cryptex-fs-password");
    options.password_hash = Some(argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(1024, 16, 1, Some(64)).unwrap()));
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