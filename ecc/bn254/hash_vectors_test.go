package bn254

func init() {
	encodeToG1Vector = encodeTestVector{
		dst: []byte("QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_"),
		cases: []encodeTestCase{
			{
				msg: "", P: point{"0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925", "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11"},
				Q: point{"0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925", "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11"},
				u: "0xcb81538a98a2e3580076eed495256611813f6dae9e16d3d4f8de7af0e9833e1",
			}, {
				msg: "abc", P: point{"0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332", "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7"},
				Q: point{"0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332", "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7"},
				u: "0xba35e127276e9000b33011860904ddee28f1d48ddd3577e2a797ef4a5e62319",
			}, {
				msg: "abcdef0123456789", P: point{"0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1", "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa"},
				Q: point{"0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1", "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa"},
				u: "0x11852286660cd970e9d7f46f99c7cca2b75554245e91b9b19d537aa6147c28fc",
			}, {
				msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", P: point{"0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b", "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06"},
				Q: point{"0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b", "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06"},
				u: "0x174d1c85d8a690a876cc1deba0166d30569fafdb49cb3ed28405bd1c5357a1cc",
			}, {
				msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", P: point{"0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84", "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0"},
				Q: point{"0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84", "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0"},
				u: "0x73b81432b4cf3a8a9076201500d1b94159539f052a6e0928db7f2df74bff672",
			},
		}}
	hashToG1Vector = hashTestVector{
		dst: []byte("QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_"),
		cases: []hashTestCase{
			{
				msg: "", P: point{"0xa976ab906170db1f9638d376514dbf8c42aef256a54bbd48521f20749e59e86", "0x2925ead66b9e68bfc309b014398640ab55f6619ab59bc1fab2210ad4c4d53d5"},
				Q0: point{"0xe449b959abbd0e5ab4c873eaeb1ccd887f1d9ad6cd671fd72cb8d77fb651892", "0x29ff1e36867c60374695ee0c298fcbef2af16f8f97ed356fa75e61a797ebb265"},
				Q1: point{"0x19388d9112a306fba595c3a8c63daa8f04205ad9581f7cf105c63c442d7c6511", "0x182da356478aa7776d1de8377a18b41e933036d0b71ab03f17114e4e673ad6e4"},
				u0: "0x2f87b81d9d6ef05ad4d249737498cc27e1bd485dca804487844feb3c67c1a9b5", u1: "0x6de2d0d7c0d9c7a5a6c0b74675e7543f5b98186b5dbf831067449000b2b1f8e",
			}, {
				msg: "abc", P: point{"0x23f717bee89b1003957139f193e6be7da1df5f1374b26a4643b0378b5baf53d1", "0x4142f826b71ee574452dbc47e05bc3e1a647478403a7ba38b7b93948f4e151d"},
				Q0: point{"0x1452c8cc24f8dedc25b24d89b87b64e25488191cecc78464fea84077dd156f8d", "0x209c3633505ba956f5ce4d974a868db972b8f1b69d63c218d360996bcec1ad41"},
				Q1: point{"0x4e8357c98524e6208ae2b771e370f0c449e839003988c2e4ce1eaf8d632559f", "0x4396ec43dd8ec8f2b4a705090b5892219759da30154c39490fc4d59d51bb817"},
				u0: "0x11945105b5e3d3b9392b5a2318409cbc28b7246aa47fa30da5739907737799a9", u1: "0x1255fc9ad5a6e0fb440916f091229bda611c41be2f2283c3d8f98c596be4c8c9",
			}, {
				msg: "abcdef0123456789", P: point{"0x187dbf1c3c89aceceef254d6548d7163fdfa43084145f92c4c91c85c21442d4a", "0xabd99d5b0000910b56058f9cc3b0ab0a22d47cf27615f588924fac1e5c63b4d"},
				Q0: point{"0x28d01790d2a1cc4832296774438acd46c2ce162d03099926478cf52319daba8d", "0x10227ab2707fd65fb45e87f0a48cfe3556f04113d27b1da9a7ae1709007355e1"},
				Q1: point{"0x7dc256c7aadac1b4e1d23b3b2bbb5e2ffd9c753b9073d8d952ead8f812ce1b3", "0x2589008b2e15dcb3d16cdc1fed2634778001b1b28f0ab433f4f5ec6635c55e1e"},
				u0: "0x2f7993a6b43a8dbb37060e790011a888157f456b895b925c3568690685f4983d", u1: "0x2677d0532b47a4cead2488845e7df7ebc16c0b8a2cd8a6b7f4ce99f51659794e",
			}, {
				msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", P: point{"0xfe2b0743575324fc452d590d217390ad48e5a16cf051bee5c40a2eba233f5c", "0x794211e0cc72d3cbbdf8e4e5cd6e7d7e78d101ff94862caae8acbe63e9fdc78"},
				Q0: point{"0x1c53b05f2fce15ba0b9100650c0fb46de1fb62f1d0968b69151151bd25dfefa4", "0x1fe783faf4bdbd79b717784dc59619106e4acccfe3b5d9750799729d855e7b81"},
				Q1: point{"0x214a4e6e97adda47558f80088460eabd71ed35bc8ceafb99a493dd6f4e2b3f0a", "0xfaaeb29cc23f9d09b187a99741613aed84443e7c35736258f57982d336d13bd"},
				u0: "0x2a50be15282ee276b76db1dab761f75401cdc8bd9fff81fcf4d428db16092a7b", u1: "0x23b41953676183c30aca54b5c8bd3ffe3535a6238c39f6b15487a5467d5d20eb",
			}, {
				msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", P: point{"0x1b05dc540bd79fd0fea4fbb07de08e94fc2e7bd171fe025c479dc212a2173ce", "0x1bf028afc00c0f843d113758968f580640541728cfc6d32ced9779aa613cd9b0"},
				Q0: point{"0x2298ba379768da62495af6bb390ffca9156fde1dc167235b89c6dd008d2f2f3b", "0x660564cf6fce5cdea4780f5976dd0932559336fd072b4ddd83ec37f00fc7699"},
				Q1: point{"0x2811dea430f7a1f6c8c941ecdf0e1e725b8ad1801ad15e832654bd8f10b62f16", "0x253390ed4fb39e58c30ca43892ab0428684cfb30b9df05fc239ab532eaa02444"},
				u0: "0x48527470f534978bae262c0f3ba8380d7f560916af58af9ad7dcb6a4238e633", u1: "0x19a6d8be25702820b9b11eada2d42f425343889637a01ecd7672fbcf590d9ffe",
			},
		}}
	encodeToG2Vector = encodeTestVector{
		dst: []byte("QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_NU_"),
		cases: []encodeTestCase{
			{
				msg: "", P: point{"0x103d2ca25313c885ace0b0a3ad64b07937976c9b8737a5033173f9436c08f0a0,0x155a3ef7ca6e82800b449b3cd1a4d8a04758ba37c43e33d9e1575f97a90f1f2", "0x14dd7085906cab369121e344725548cf669c1a5ee9cdb68b043f9c5b5cc48437,0xc5d30c7ad530f8a076b1519d4cd86bf0cbf9a769187008aea3e64153f0f7134"},
				Q: point{"0x2975d590bf27fc8ca489cc7c8b540708bba6cd4d23b70940b90ae0d62c1d0a05,0x2af74971da097422e19a9ddb4bdda405b5a357afd4e57543a6e6b6773875ac6", "0x2b2041171f73e5a97cc80a53c7697908b757e6fdab1f5c7a7c0e6fe432da07f7,0x1d1efe72383527a223848e33e7cbcf1a69946d07e67e06a6307e6b2fb6be1308"},
				u: "0x5952a51e848675c06172da425edc1c471c11db4bc51cfb84c097bdbcf22b6b5,0x4f8c1f037b231d08ea68f3e23b8e3c708d3993a1577d1bcfc92c2392a82c47e",
			}, {
				msg: "abc", P: point{"0x7cd9a42badb2d388a6002a4786bf3b6f897956dcfde6d4b2a9b698572bdcf1f,0x20677f5e2bfc7a59c7507703e86717173edb1c61c0818233c45111d09230dcc4", "0x27f607a21bdd45512347be0ec14990f97c32529f9d9a5aca1d9fd95e1423aabd,0x1cab09de4113e44365df2ebcd4925fd3404fc2021041e612859e70964cd49aae"},
				Q: point{"0x19a79222ecdc56f69080f2bacc26e2b534b4895b305074970c9590ae1078a318,0xfbf3578cbc385536cdfdaf5eb90f174323f59e868f14564845f0065a71c4555", "0x1dea5e5c5147afe3edcef8ed960720f22a18fae2d6092f50abfe1033f5143f00,0x1be3a4e18dd61a3619da250509f1aea022f7247e63467ec45fad6da62b7c02e3"},
				u: "0x25f701986d04721d21b118002eeaad1b8ecc8de722d4d8e7ad5f060518ea5c7c,0xf05f22acfb3bf7abb1f8f1b80e0de029a20a2b96c6eefa2f371431bbfca04a3",
			}, {
				msg: "abcdef0123456789", P: point{"0x148afd92912a9a1cd1d651a44ca2f9f37f58e8ac423098940e699c6cfc470f13,0x2bf060121ff99dd02613d1277b08401ca622897864f9b91c6fd2f27eb70fa898", "0x1364a7da86cf448699e90608d7097e593842b823fb9fd674ed3e741eda5bf650,0x294ba525162ddd03efb3501e5c1f6c8d9f50a1b25232914dd9460dd0551410fd"},
				Q: point{"0x10d9abd442523ee0e877a3217706666126644f8274824980ac2b8192129c921a,0x10bc1b1ac7b7634916462387461a29c128209f58d16e922910c3816b3dfc518c", "0xf59b63caeb02d7e3a02710ecbce95bcb9afd60c1271cecbc895bbce204779bc,0x14531069a6ab0303934c820ac199f717d94012d24e120f2a2d59281c6bf9f239"},
				u: "0xeb05b113763043309faadf3c004ac0eb40f948faed5d83d4d1f0571112ca09c,0x1730924259ae2e94ae7ee719c1eeb5d6328b6963819ee4065541dfdefb5e7a07",
			}, {
				msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", P: point{"0x21ac4d17666a2a752d955c48288fda816bd6deac11e52f5ad51a73baa18c685c,0x2d6b1a2055564be823c05895b842e4aa8e6e9dc5ed6a8cf86b143e0a20ad045c", "0x19c23470850d68b0f8bd7da3c33d2ed36b28d5adf59cc2a3950dcbb9045b193d,0x1703b1adc2d4267a7aa369fbbaf044ac7d3f592f36847f99a019432e36365520"},
				Q: point{"0x2c190e16d196bc3eeff3805a1ae716b8c6b0b48fc642490f0add99a7d5b3c2f2,0x1bcdea6ab69506e752fffe6cfc84011dc8881e740688cf0f7f631acf21600fb2", "0x14a9eb70c86c20ac7060fff17e4961d9700f7544910b7b91696b1db1bd336167,0x29cefbaf1de2a3c7fb490fe919c5d14dab23c1b2e562aa402249369074d46a56"},
				u: "0x47b36a3ec43c92ae9070ef71f85016bd5a08c1bd0ca487672f176061ca09159,0x248076a8b63f52e5f3c7228411637e04cbd0cb36940ee3a257f60ce49e75fe86",
			}, {
				msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", P: point{"0x26e9c09f4521b799f83f138ecc0f337c62b40ba23c56dde01217a1ee3cf6fd71,0xd0475821f47ffb77fbe3bf02e2dd6f54585c3219b82d93e62ff82d032995d7", "0x12dfde03f670f7f38822c688755872518e9e8a270c52b321eaccfd3afe0a47b,0x1e3117db468c00633529e307848147f52fbe43b9466d8e910d94788c8a3cd634"},
				Q: point{"0x1ae048585c22fd3d3fd638f433adee4900067115392c713bf4f0b63689b5a1d0,0xc5ced407f53acf4a9d9008f11f4d353c220ee1f9ff69839c5639167cb297220", "0x3006ea33cdf08c52930be190a898cf55457a486ef41429f1b0595100a1331c90,0x3006eec9025115ac3d91bde07bd02675b9f0c8b595b7da4df4ffeeecc0b0a5f1"},
				u: "0x2f3b24a712fbb1272e51db197d666cdad2cc94c2a6e7b77d99e97d8a705a8a50,0x253bcb542b718219fe2f6de276c6d86965d610b3e66bd0448576db18e1e9ab3f",
			},
		}}
	hashToG2Vector = hashTestVector{
		dst: []byte("QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_RO_"),
		cases: []hashTestCase{
			{
				msg: "", P: point{"0xed0d40000f45c0ccb22f6d4b5556a622aeae7171bc7786384388c72c2d1c457,0x16cdd0997f60c1db037b92d2a1547807cdd197452dcf022939d1319ee0b54734", "0x22cbeff2598127f6bd6d978719090096fcb12ecd4963ff6cc319e5cdc81292a9,0x8a263f06c6eef04278720d7b1d775b3d089b11cd333d85b4e7b8b5d8aee0407"},
				Q0: point{"0x2c2967a938ddc0603d81f2a2633b6d7c05ba44b1ab92309f1f3b5b99d51c80a8,0x1932b6c4eac530eed69030d75613150b71f7436452c4c5dfb0ad1af026b58ba3", "0x3e7b07b5934c95473a1a2db7e248862bec939558607acbeaa21a2cca05d6279,0xc437e37af1694bed5866cb4eb89e6161e0d1d395422bd503a3e02ee5491f539"},
				Q1: point{"0x13b6d6e0f63c411a32ef044a22a28daab75e01360c0381b931d6462340c2c2ca,0x1dd7f5afbb92443adad1d6c711fa0e05dceb029d442f941f62713e61cc87c442", "0x2439bf2836f601acb3f6081ba98e57f53fce08d3b4d6d69c3d217eae6113901b,0x15c4657a59f56311e051bd4ab4a4c1f4ee90d70dcd7b0112a94747d919e6a762"},
				u0: "0x2c85988ecf26034a6d6c495c467150aeaead51fceb623aa99b0433275c8952c7,0x182126b31e6df7cf33844bf16a92f42072ee47f80539dace68dbfc3380d1fcbd", u1: "0x1c3035901eab4768d522b3d0eb7e58b05c130603c8f43587345dc51745fa3533,0x23597b1c4f238038ba6579d203e7fcb7d427c63d4e0d037185453168718203bb",
			}, {
				msg: "abc", P: point{"0x1a157379821af76197c91be2edaa32896367ec7928c067e6915a03009987517e,0x17c113afe7b749ff849e6920b0f72ce986eaaca1e5b7c467be6e88c7aab5c962", "0x116a0553a3b974ae27aff261e6503477ee021839b0139f58655fad1460b738b7,0xe481714afa543e91943b8ae6894bd64d43d1481c8081a43ee7f857397ffe8d3"},
				Q0: point{"0x2dd5011829cf0c9410b1679ac27d3d439e570e656af4289cd50a4580db05ea7d,0x1823563b20c0cc9f3f444c8b01a39a9c5f6290e7ee9d9960b8e4cca087d8bb8", "0x1e93b76f96523a416d937a484d675392a937877b549ceeb2392b4533a83bc417,0x184c990cc5be545541b8f770b927511d1cec842e202d1b512a7177c8822fc675"},
				Q1: point{"0x27cc1aff04e704b8a0be773570f4006d09cefc3aae330986160c94efe0438dba,0x1a68505a5bf6f5aa3c87091f87fc72dbe0f4a49dc5d020225a0e6996c870ac73", "0xebff615833163c02beeacc6aa9c462421959d6b52fd0fb3d96988bec79594a3,0x27bddfb7178ebdfc9b61cb44d84f7191cbdaed4fdf9c4670a3debcbf6978267f"},
				u0: "0x234b244ed36d5acbb96a4f5fb67094945a0bb4ecf33d55bcc218ce834dc82c63,0x4ca11f51d0cf7e7393a0e6d7be3d0e6b07652d5ba308554a72dafe502dd59cc", u1: "0x1c31ec87881353ec57fc87c27e31099a0705390c52dbfc8c047d14260658df71,0x2daa8e05eb3367285b5de508d248b3153207498f3e9e51cbe6183ff7dae286a6",
			}, {
				msg: "abcdef0123456789", P: point{"0xf07cab202d08b8d3cde56c6c7f5a39a2d35258cf6f4d6664edf6d8912fa56dd,0x2932a6df266b0fd00201295dce06788e882bb863bc8d21cb6f1651ffc23ebefa", "0x3346da40e86b4e4a93f4f7997587c2318f8e16df00f36ce41e09a1d84b73092,0x102e1b8b212283cf2c68bd650441d351ed3e8055c2ae4aec221a4bde438dfd7d"},
				Q0: point{"0x3c5f1ac17aac32447380c9a338cfdf941470a1e9fdd58d19363e9b077f57b01,0x257f0544a9c2e66e730aecd6775ce50f7e8fde1519882c20d3855ee94f618c0c", "0x2c11dafd3e9de5dfdb48cd8a04f4139b83c8c88646a31d969d2be335a71403f,0x2e45f11317bd4c1d0b59f2279e10de9464d6d90e1f7a2475d5f8110c0fed4bd8"},
				Q1: point{"0x651c8649fb5e1c7f2df354a60551e050448df65f561f3fbdb188ed1293cb36a,0x6d396f43c813c80cf4eb410c06d68be8e6e9ca68351fdf8ebbff4701f012007", "0x2c496df8f87bbddc174c58d48d378a12fe8eeef9cb67637430982fbe40cb3102,0x29b3bde8ff7f2353a9047f4138474db334e192c1b54ff95c49efcad8c6d2a3fd"},
				u0: "0x29c7f821157ab18e589d1e7d7bd393d20aff69af2ac4deadc7950998d594d201,0x860010a5c2ae9289f0d4f7099ff0d5904ded06f99d5960f734de36b82ff983c", u1: "0x1f3c50c3ccfbaad8e81f8a765c5465a034b55fb873be48fd60dc21fb2cca98b8,0x2fa095cba1059ef5e2d5ea1c976a87f4530225aa7759b5b9510bb76d7b1d4f3",
			}, {
				msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", P: point{"0x2fcb6bd31a83cecad0ca27a1c2412e85924db60d1b171e47239fb93e315d6f37,0x32e3578a4d297dd830c6d0acf9565df67c8d5d208b9a4246d60c623d212cf2e", "0xe5dfbcb4a8de23fe749a9a2ce7824a315f2f5af392f5bb748faf4f7df796e52,0x1612016e04afecdf0f3f62920791d72d4ced3885b06b2b51ea89c6beb09ab5ae"},
				Q0: point{"0x1f6d399997c1b51badf6852cd6d7be34405f8c1fe219085af3e96449bbbb46af,0xfb0f9c66b952989d1616293d44769ea273fa73eb66db1fc57958c81a11f4b0c", "0x1f0e4c948bf2257592c82c989006e7f09c54d0e09fb7e593d770b2696a081fa1,0x2f73c149f6737963d76987054f52033b68a9606e0bc514977669fd5bf3fb6c0e"},
				Q1: point{"0x110efe0190dafd8b99af329e4718e1035c9e83abed0924c0847d6035766514a0,0x224076f8e696abc162e0b9bc9f8eed1c8d52fca7ebbcbdd5c59d3cd2dd344d60", "0xc49f9e0b16fb31d46070e6b2383f7ccd109d5e8015db3c28d77d8659089134b,0x1d6012d91cab0ff7bc33a06d4304a9fac5c055bf290845b0b147255d5d644d18"},
				u0: "0x859e4f9b60f7ce13f81da9da46435c8827ed53f553b4e1804a395af1354b2c7,0x368bfd8f29d990293171aee9be3bc4ad623c54d0db776d0fe87cfd579059a86", u1: "0x103aa84a49f14d0ca1dfda47fa93a43cece0c267ae8799123d63ccd027772f71,0x9ebcb7d529f69c5e7ab096ff1a727ec8bc6c5214ed1784cd7f9e325e121640c",
			}, {
				msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", P: point{"0x2dec143936c0cc57fdad2091b0a6565b704876c9656de3beecc262c3df4994ce,0x9b5b8c980ff9a142f412329e6799e101e6330c459b49faa1617c88d245e60e8", "0x290eee412ea2c138bcc0b20fcaef8f38ea86e6f6c3af74accdccc1ca8c0a5524,0x1c2de882b68eb5580f15fd96b9d7f79ce0bbb09ad8a906237d9ac9f82e9c64ec"},
				Q0: point{"0x1860a769becf757dd40bd0e0f98d9747780eae60c976a2265f274fe0695bf65a,0x12a58da387897891ff22beaa3ae746786308e7cd0e4f6123de2271a4cad6642c", "0x1ac22839c0b5e8dfdffa6d2c6851f386088348c9726fc36bdf2a266fec4cab7d,0x2ffb96872a65e7c2dee0b4fc24d8d7d343b1b58abf67c08caa8f3f3e53914a45"},
				Q1: point{"0x21d7ab4b3b08fd26744d1dbf8b285e1fa087be8f9fc7ee0792e7813c30ce0455,0x1469072d185575bead7abfa74545695c766b762080486227f21163738312544f", "0x23df59913dbf81edb9217064ac180c01498d9760e498b0af9dc2df3329c94a6a,0x230bcff5530832a4027e90e2c6fb9a0066fa97a69e00a6dd8e3d5912ac3a1b99"},
				u0: "0xf0a229a329e3df7fe4feea02aac7dad3a01d345f65efe512544699439aacd83,0x15b85241a3f8790e550026f37fd861babd3dba9e2bce0deced2df56f7440bbb4", u1: "0xfa59525a85744763ea88a78ca612cb8db4d6e08f3d192568749b90ef16c36b6,0x1c32e85696693c537a91a4283353fba8c24f4107278b82990cc0c595a4d4f6cc",
			},
		}}
}