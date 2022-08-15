pub mod compressed_points;

#[cfg(test)]
mod tests {
    use crate::compressed_points::CompressedEdwardsX;
    use crate::compressed_points::EdwardsPointExt;
    use curve25519_dalek::edwards::EdwardsPoint;
    use hex::FromHex;

    use curve25519_dalek::edwards::CompressedEdwardsY;

    #[test]
    fn compressed_x() {
        let expected_compressed_x =
            "A3D966BB6B27D4B1E7CF45F3C96A32B1D868BFFCAC91846412E67481EFE82659";
        let expected_compressed_y =
            "1EE08564F758E3B2FDA686428D29D008E31D3D9B3F8E4CE51A80C0544A15FFA4";
        let compressed_bytes_x =
            <[u8; 32]>::from_hex(expected_compressed_x).expect("Decoding failed");
        let compressed_bytes_y =
            <[u8; 32]>::from_hex(expected_compressed_y).expect("Decoding failed");
        let cy = CompressedEdwardsY(compressed_bytes_y);
        let decomp_from_y: EdwardsPoint = cy.decompress().unwrap();

        let comp_x = decomp_from_y.compress_x();
        assert_eq!(comp_x.as_bytes(), &compressed_bytes_x);
    }

    #[test]
    fn decompress_x() {
        let expected_compressed_x =
            "A3D966BB6B27D4B1E7CF45F3C96A32B1D868BFFCAC91846412E67481EFE82659";
        let expected_compressed_y =
            "1EE08564F758E3B2FDA686428D29D008E31D3D9B3F8E4CE51A80C0544A15FFA4";
        let compressed_bytes_x =
            <[u8; 32]>::from_hex(expected_compressed_x).expect("Decoding failed");
        let compressed_bytes_y =
            <[u8; 32]>::from_hex(expected_compressed_y).expect("Decoding failed");
        let cx = CompressedEdwardsX(compressed_bytes_x);
        let decomp_from_x: EdwardsPoint = cx.decompress().unwrap();

        let comp_y = decomp_from_x.compress();
        assert_eq!(comp_y.as_bytes(), &compressed_bytes_y);
    }

    #[test]
    fn compression_circle() {
        let expected_compressed_x =
            "A3D966BB6B27D4B1E7CF45F3C96A32B1D868BFFCAC91846412E67481EFE82659";
        let expected_compressed_y =
            "1EE08564F758E3B2FDA686428D29D008E31D3D9B3F8E4CE51A80C0544A15FFA4";
        let compressed_bytes_x =
            <[u8; 32]>::from_hex(expected_compressed_x).expect("Decoding failed");
        let compressed_bytes_y =
            <[u8; 32]>::from_hex(expected_compressed_y).expect("Decoding failed");
        let cy = CompressedEdwardsY(compressed_bytes_y);

        let decomp_from_y: EdwardsPoint = cy.decompress().unwrap();
        let comp_x = decomp_from_y.compress_x();
        assert_eq!(comp_x.as_bytes(), &compressed_bytes_x);

        let decomp_from_x = CompressedEdwardsX::decompress(&comp_x).unwrap();
        assert_eq!(decomp_from_y, decomp_from_x);
    }
}
