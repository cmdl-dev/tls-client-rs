use std::time::Duration;

use serde_json::Value;
use tls_rust::{ClientBuilder, ClientProfile, Request};

const PEET_API_URL: &str = "https://tls.peet.ws/api/all";

#[derive(Clone, Copy)]
struct ProfileExpectation {
    profile: ClientProfile,
    ja3: &'static str,
    ja3_hash: &'static str,
    akamai_fingerprint: &'static str,
    akamai_fingerprint_hash: &'static str,
}

const EXPECTATIONS: &[ProfileExpectation] = &[
    ProfileExpectation {
        profile: ClientProfile::Chrome103,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome104,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome105,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome106,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome107,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome108,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome109,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome110,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-27-18-51-17513-0-16-35-11-5-65281-43-13-45-10-21,29-23-24,0",
        ja3_hash: "f30e7d05622c38802b2ee65d147f4df8",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome111,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-11-17513-5-10-18-23-0-45-51-43-35-65281-16-13-21,29-23-24,0",
        ja3_hash: "499d7c2439dc2fb83d1ab2e52b9dc680",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome112,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-51-17513-43-0-11-5-23-16-10-65281-27-18-35-13-21,29-23-24,0",
        ja3_hash: "7f052aeccc9b50e9b3a43a02780539b2",
        akamai_fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "a345a694846ad9f6c97bcc3c75adbe26",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome117,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-0-16-13-43-17513-10-23-35-27-18-5-51-65281-11-21,29-23-24,0",
        ja3_hash: "1ddf8a0ebd957d10c1ab320b10450028",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome120,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-45-43-5-23-35-13-65281-16-65037-18-51-10-11-17513-27,29-23-24,0",
        ja3_hash: "1d9a054bac1eef41f30d370f9bbb2ad2",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome124,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-18-23-17513-16-43-13-11-0-35-10-65037-5-65281-45-51,25497-29-23-24,0",
        ja3_hash: "64aff24dbef210f33880d4f62e1493dd",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome131,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-65037-65281-18-27-16-5-10-17513-11-51-35-43-45-0-23,4588-29-23-24,0",
        ja3_hash: "a19ab9f02aacf42deddc1f2acb3d3f63",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome133,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-13-17613-51-18-11-43-5-16-0-65037-27-10-45-23-65281,4588-29-23-24,0",
        ja3_hash: "74e530e488a43fddd78be75918be78c7",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Chrome144,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-0-17613-65281-10-27-35-5-23-43-13-18-11-65037-16-45,4588-29-23-24,0",
        ja3_hash: "f984bd5bc7358922cde86ed4471a2e89",
        akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "52d84b11737d980aef856699f885ca86",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox102,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox104,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox105,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox106,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox108,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox110,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-21,29-23-24-25-256-257,0",
        ja3_hash: "ad55557b7cbd735c2627f7ebb3b3d493",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox117,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        ja3_hash: "579ccef312d18482fc42e2b822ca2430",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox120,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0",
        ja3_hash: "ed3d2cb3d86125377f5a4d48e431af48",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox123,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
        ja3_hash: "b5001237acdf006056b409cc433726b0",
        akamai_fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        akamai_fingerprint_hash: "3d9132023bf26a71d40fe766e5c24c9d",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox132,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0",
        ja3_hash: "a767f8ae9115cc5752e5cff59612e74f",
        akamai_fingerprint: "1:65536;2:0;4:131072;5:16384;9:1|12517377|0|m,p,a,s",
        akamai_fingerprint_hash: "a80d4d15d0c3bdd7b34b39d61cdaf0f7",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox133,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0",
        ja3_hash: "a767f8ae9115cc5752e5cff59612e74f",
        akamai_fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        akamai_fingerprint_hash: "6ea73faa8fc5aac76bded7bd238f6433",
    },
    ProfileExpectation {
        profile: ClientProfile::Firefox147,
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
        ja3_hash: "6f7889b9fb1a62a9577e685c1fcfa919",
        akamai_fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        akamai_fingerprint_hash: "6ea73faa8fc5aac76bded7bd238f6433",
    },
    ProfileExpectation {
        profile: ClientProfile::Opera89,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Opera90,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Opera91,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        akamai_fingerprint: "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
        akamai_fingerprint_hash: "4f04edce68a7ecbe689edce7bf5f23f3",
    },
    ProfileExpectation {
        profile: ClientProfile::Safari15_6_1,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:4194304;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "dda308d35f4e5db7b52a61720ca1b122",
    },
    ProfileExpectation {
        profile: ClientProfile::Safari16,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:4194304;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "dda308d35f4e5db7b52a61720ca1b122",
    },
    ProfileExpectation {
        profile: ClientProfile::SafariIpad15_6,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:2097152;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "d5fcbdc393757341115a861bf8d23265",
    },
    ProfileExpectation {
        profile: ClientProfile::SafariIos15_5,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:2097152;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "d5fcbdc393757341115a861bf8d23265",
    },
    ProfileExpectation {
        profile: ClientProfile::SafariIos15_6,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:2097152;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "d5fcbdc393757341115a861bf8d23265",
    },
    ProfileExpectation {
        profile: ClientProfile::SafariIos16_0,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "4:2097152;3:100|10485760|0|m,s,p,a",
        akamai_fingerprint_hash: "d5fcbdc393757341115a861bf8d23265",
    },
    ProfileExpectation {
        profile: ClientProfile::Safari18_5,
        ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
        ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
        akamai_fingerprint: "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
        akamai_fingerprint_hash: "c52879e43202aeb92740be6e8c86ea96",
    },
    ProfileExpectation {
        profile: ClientProfile::SafariIos26,
        ja3: "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0",
        ja3_hash: "ecdf4f49dd59effc439639da29186671",
        akamai_fingerprint: "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
        akamai_fingerprint_hash: "c52879e43202aeb92740be6e8c86ea96",
    },
    ProfileExpectation {
        profile: ClientProfile::OkHttp4Android12,
        ja3: "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
        ja3_hash: "f79b6bad2ad0641e1921aef10262856b",
        akamai_fingerprint: "4:16777216|16711681|0|m,p,a,s",
        akamai_fingerprint_hash: "605a1154008045d7e3cb3c6fb062c0ce",
    },
    ProfileExpectation {
        profile: ClientProfile::OkHttp4Android13,
        ja3: "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
        ja3_hash: "f79b6bad2ad0641e1921aef10262856b",
        akamai_fingerprint: "4:16777216|16711681|0|m,p,a,s",
        akamai_fingerprint_hash: "605a1154008045d7e3cb3c6fb062c0ce",
    },
];

fn is_known_live_transport_limitation(profile: ClientProfile) -> bool {
    matches!(profile, ClientProfile::Chrome120)
}

#[tokio::test]
#[ignore = "Live fingerprint test ported from Go profile expectations"]
async fn ported_profiles_match_expected_fingerprints() {
    for case in EXPECTATIONS {
        if is_known_live_transport_limitation(case.profile) {
            continue;
        }
        let payload = capture_from_rust(case.profile).await;

        assert_eq!(
            string_at_path(&payload, "tls.ja3"),
            case.ja3,
            "{}",
            case.profile.as_key()
        );
        assert_eq!(
            string_at_path(&payload, "tls.ja3_hash"),
            case.ja3_hash,
            "{}",
            case.profile.as_key()
        );
        assert_eq!(
            string_at_path(&payload, "http2.akamai_fingerprint"),
            case.akamai_fingerprint,
            "{}",
            case.profile.as_key()
        );
        assert_eq!(
            string_at_path(&payload, "http2.akamai_fingerprint_hash"),
            case.akamai_fingerprint_hash,
            "{}",
            case.profile.as_key()
        );
    }
}

async fn capture_from_rust(profile: ClientProfile) -> Value {
    let client = ClientBuilder::new()
        .profile(profile)
        .timeout(Duration::from_secs(90))
        .build()
        .expect("build rust client");

    let response = client
        .execute(
            Request::get(PEET_API_URL)
                .header("accept", "*/*")
                .header("accept-encoding", "gzip")
                .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36",
                ),
        )
        .await
        .expect("perform rust capture request");

    let body = response.text().await.expect("read rust capture body");
    serde_json::from_str(&body).expect("decode rust capture response")
}

fn string_at_path<'a>(value: &'a Value, path: &str) -> &'a str {
    let mut current = value;
    for segment in path.split('.') {
        current = current
            .get(segment)
            .unwrap_or_else(|| panic!("missing `{path}` in payload"));
    }
    current
        .as_str()
        .unwrap_or_else(|| panic!("`{path}` was not a string"))
}
