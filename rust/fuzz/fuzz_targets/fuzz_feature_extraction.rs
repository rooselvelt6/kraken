#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let extractor = localmodels::features::FeatureExtractor::new();
        let features = extractor.extract(s);
        let vec = features.as_feature_vec();
        // Verify feature vector is always the expected length
        assert_eq!(vec.len(), 66);
    }
});
