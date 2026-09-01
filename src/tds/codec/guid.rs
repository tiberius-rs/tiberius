/// UUIDs use network byte order (big endian) for the first 3 groups,
/// while GUIDs use native byte order (little endian).
///
/// https://github.com/microsoft/mssql-jdbc/blob/bec39dbba9544aef5f5f6a5495d5acf533efd6da/src/main/java/com/microsoft/sqlserver/jdbc/Util.java#L708-L730
pub(crate) fn reorder_bytes(bytes: &mut uuid::Bytes) {
    bytes.swap(0, 3);
    bytes.swap(1, 2);
    bytes.swap(4, 5);
    bytes.swap(6, 7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorder_bytes_swaps_the_guid_groups() {
        // Swaps within the first three groups (0<->3, 1<->2, 4<->5, 6<->7); the
        // trailing 8 bytes are left in place.
        let mut bytes: uuid::Bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        reorder_bytes(&mut bytes);
        assert_eq!(
            bytes,
            [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn reorder_bytes_is_its_own_inverse() {
        let original: uuid::Bytes = [
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ];
        let mut bytes = original;
        reorder_bytes(&mut bytes);
        assert_ne!(bytes, original);
        reorder_bytes(&mut bytes);
        assert_eq!(bytes, original);
    }
}
