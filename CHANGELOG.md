# Changelog

## [0.51.0](https://github.com/mctlhq/mctl-telegram/compare/0.50.1...0.51.0) (2026-08-23)


### Features

* **session:** exempt named identities from the absolute session TTL ([ed1ad65](https://github.com/mctlhq/mctl-telegram/commit/ed1ad6503af4c04ccbb85d8b65f4ad49688f67c2))


### Bug Fixes

* **session:** keep exempt rows out of the Migrate backfill ([b9e4739](https://github.com/mctlhq/mctl-telegram/commit/b9e47397ea5d62260436fea3f63ad4bf908e4409))

## [0.50.1](https://github.com/mctlhq/mctl-telegram/compare/0.50.0...0.50.1) (2026-08-18)


### Bug Fixes

* **config:** cap OAUTH_ACCESS_TOKEN_TTL ([#398](https://github.com/mctlhq/mctl-telegram/issues/398)) ([78b3fc6](https://github.com/mctlhq/mctl-telegram/commit/78b3fc62d28684aae47d6b23c664214fe38c00e2))
* **mcp:** prioritize DMs in unread fetch and set last_message_date ([#396](https://github.com/mctlhq/mctl-telegram/issues/396)) ([dca0996](https://github.com/mctlhq/mctl-telegram/commit/dca0996d822b17e6abb172cff9f8b48602117e46))

## [0.50.0](https://github.com/mctlhq/mctl-telegram/compare/0.49.0...0.50.0) (2026-08-16)


### Features

* **oauth:** make the implicit-host allowlist configurable ([#394](https://github.com/mctlhq/mctl-telegram/issues/394)) ([3513176](https://github.com/mctlhq/mctl-telegram/commit/35131762a926aab167ebd84f316b9d7e8dd51f6a))

## [0.49.0](https://github.com/mctlhq/mctl-telegram/compare/0.48.0...0.49.0) (2026-08-15)


### Features

* **ui:** Onest, terracotta default, remove accent picker ([b54ef4d](https://github.com/mctlhq/mctl-telegram/commit/b54ef4dc299e06da2ff76f03a6cae348fa868693))
* **ui:** remove the header accent color picker ([2b63717](https://github.com/mctlhq/mctl-telegram/commit/2b637179a1ae5076d784f0ed1518a324db6e40ad))


### Bug Fixes

* replace leftover cyan local favicon with terracotta T ([a6882cf](https://github.com/mctlhq/mctl-telegram/commit/a6882cfdd9376fb81b3d076c5a63928b45fe9b30))
* replace leftover cyan local favicon with terracotta T ([7655beb](https://github.com/mctlhq/mctl-telegram/commit/7655beb295bf02dfcceb65ef6df298d0aa9f21da))

## [0.48.0](https://github.com/mctlhq/mctl-telegram/compare/0.47.0...0.48.0) (2026-08-15)


### Features

* **ui:** load the telegram favicon from the design CDN ([e467a45](https://github.com/mctlhq/mctl-telegram/commit/e467a458013704172c055d2f485e245d2bf09cdc))
* **ui:** load the telegram favicon from the design CDN ([fd1a27c](https://github.com/mctlhq/mctl-telegram/commit/fd1a27c61c92367cac02b837894fd9b9626ee701))


### Bug Fixes

* cache-bust the CDN telegram favicon ([dc321e0](https://github.com/mctlhq/mctl-telegram/commit/dc321e0f2bb4b03d46ebe84e0a6f828b60fb8156))

## [0.47.0](https://github.com/mctlhq/mctl-telegram/compare/0.46.0...0.47.0) (2026-08-14)


### Features

* **agent:** add TEST-ONLY crash-after-reserve hook for the random_id drill ([2b519dd](https://github.com/mctlhq/mctl-telegram/commit/2b519dda08710f4373b0d78744fda0b9740e4560))
* **agent:** add TEST-ONLY crash-after-reserve hook for the random_id drill ([51b7215](https://github.com/mctlhq/mctl-telegram/commit/51b7215eb23dffcf198cd20a2a273e800385d25e))
* **db:** use display name as fallback for telegram_username ([545b572](https://github.com/mctlhq/mctl-telegram/commit/545b5723d4c93b31620ebc7c89e810a79d395bcb))
* **db:** use display name as fallback for telegram_username ([19fdc52](https://github.com/mctlhq/mctl-telegram/commit/19fdc52a6435a2143a2b62f50c19b59300f37952))
* **docs:** add context7.json configuration for AI search indexer ([61f7090](https://github.com/mctlhq/mctl-telegram/commit/61f70904c9acc24510f2a2f48666a692dbf71d68))
* **docs:** add context7.json configuration for AI search indexer ([d0fd962](https://github.com/mctlhq/mctl-telegram/commit/d0fd962a0a72fe78473a7b4f956d7bd491e085f2))


### Bug Fixes

* **agent:** stop trusting msg.Out for Saved Messages live-push commands ([a49a0b9](https://github.com/mctlhq/mctl-telegram/commit/a49a0b9570e9544f619a3a339bf756fa6664aa78))
* **agent:** stop trusting msg.Out for Saved Messages live-push commands ([59c0ec4](https://github.com/mctlhq/mctl-telegram/commit/59c0ec4d9bfe659a6be635a980d50d6fdd5434a5))
* **auth:** emit WWW-Authenticate resource_metadata on invalid token ([170002a](https://github.com/mctlhq/mctl-telegram/commit/170002ae8f6f4564ed8bca540756345d5eea06b4))
* **auth:** emit WWW-Authenticate resource_metadata on invalid token ([b27f706](https://github.com/mctlhq/mctl-telegram/commit/b27f7060a3cb90a54f6b781939d0163cfedeb0bb))
* **oauth:** reject userinfo and backslash in implicit redirect URIs ([#377](https://github.com/mctlhq/mctl-telegram/issues/377)) ([dba713e](https://github.com/mctlhq/mctl-telegram/commit/dba713ee767d2490c44d963e55d704a52f29675a))

## [0.46.0](https://github.com/mctlhq/mctl-telegram/compare/0.45.0...0.46.0) (2026-07-31)


### Features

* **agent:** add bounded C1 validation controls ([#317](https://github.com/mctlhq/mctl-telegram/issues/317)) ([925b67f](https://github.com/mctlhq/mctl-telegram/commit/925b67f3561ff27240fc35f96deb6d395612c858))
* **agentapi:** admin-scoped PUT /api/admin/agent/profile ([#315](https://github.com/mctlhq/mctl-telegram/issues/315)) ([ca3deb4](https://github.com/mctlhq/mctl-telegram/commit/ca3deb48b2936209f8261a9af1e3eb2a39c9e105))
* **agent:** store tenant owner profiles encrypted ([#328](https://github.com/mctlhq/mctl-telegram/issues/328)) ([061933b](https://github.com/mctlhq/mctl-telegram/commit/061933b261410bc45aa85ed57930814ceaaf94ab))


### Bug Fixes

* **agent-worker:** suppress adversarial prompt echoes ([c5900eb](https://github.com/mctlhq/mctl-telegram/commit/c5900eb2f1c0c912fc3d56f36e5b1f386eaf806d))
* **agent-worker:** suppress adversarial prompt echoes ([ddc1686](https://github.com/mctlhq/mctl-telegram/commit/ddc1686c8c2021fe5d1376feb7b173805892041f))
* **agent:** bind job completion to durable result ([#331](https://github.com/mctlhq/mctl-telegram/issues/331)) ([c2fcf32](https://github.com/mctlhq/mctl-telegram/commit/c2fcf327e1328b405c83a52ab97d50a7fb290d59))
* **agent:** claim jobs with POST ([#327](https://github.com/mctlhq/mctl-telegram/issues/327)) ([314b759](https://github.com/mctlhq/mctl-telegram/commit/314b759c6ef71997896ed6c4141c0ff665945c1d))
* **agent:** poll Saved Messages commands from history ([#319](https://github.com/mctlhq/mctl-telegram/issues/319)) ([c66ae91](https://github.com/mctlhq/mctl-telegram/commit/c66ae9168fba0a54b2e5ec7070199fc4d87938dc))
* **agent:** protect approval codes at rest ([#326](https://github.com/mctlhq/mctl-telegram/issues/326)) ([54f0aab](https://github.com/mctlhq/mctl-telegram/commit/54f0aabf26baed84729898734d74ee080a83c85a))
* **agent:** saved-history poller must not gate on msg.Out ([#322](https://github.com/mctlhq/mctl-telegram/issues/322)) ([ea04c8f](https://github.com/mctlhq/mctl-telegram/commit/ea04c8fd387e87fc993a91a86dea0db58936e31f))
* **agent:** verify durable MCP job completion ([#316](https://github.com/mctlhq/mctl-telegram/issues/316)) ([d92939d](https://github.com/mctlhq/mctl-telegram/commit/d92939dcafa68bce70f0dd99f7deaa87245e95e1))
* **ci:** fail incomplete Claude reviews ([#323](https://github.com/mctlhq/mctl-telegram/issues/323)) ([2acc457](https://github.com/mctlhq/mctl-telegram/commit/2acc457baab81439e95249d7a0ad1c929116cc32))
* **oauth:** complete RFC 9728 discovery and fix scope metadata drift ([#345](https://github.com/mctlhq/mctl-telegram/issues/345)) ([6e2970b](https://github.com/mctlhq/mctl-telegram/commit/6e2970bc09f9b80c2209743f9c5754db1bbc8556))
* **oauth:** recover refresh-token rotation races instead of failing them ([#343](https://github.com/mctlhq/mctl-telegram/issues/343)) ([355cb96](https://github.com/mctlhq/mctl-telegram/commit/355cb965b37795957fabc3060b54d4dab48f3bbf))
* **telegram:** retire duplicated auth sessions ([#324](https://github.com/mctlhq/mctl-telegram/issues/324)) ([0438490](https://github.com/mctlhq/mctl-telegram/commit/0438490d2e2bbf680e2891dce997ec2637378502))

## [0.45.0](https://github.com/mctlhq/mctl-telegram/compare/0.44.1...0.45.0) (2026-07-30)


### Features

* **agent-worker:** add /livez /readyz health endpoints ([#312](https://github.com/mctlhq/mctl-telegram/issues/312)) ([665a83d](https://github.com/mctlhq/mctl-telegram/commit/665a83dc11a35350287485344f478c725459d592))
* **agent:** add bounded C1 validation controls ([#317](https://github.com/mctlhq/mctl-telegram/issues/317)) ([925b67f](https://github.com/mctlhq/mctl-telegram/commit/925b67f3561ff27240fc35f96deb6d395612c858))
* **agent:** agent-facing HTTP surface /api/agent/v1 (A-PR6) ([#306](https://github.com/mctlhq/mctl-telegram/issues/306)) ([c4864f6](https://github.com/mctlhq/mctl-telegram/commit/c4864f67c04aec6a958a2ce71c2b3449589061ac))
* **agentapi:** admin-scoped PUT /api/admin/agent/profile ([#315](https://github.com/mctlhq/mctl-telegram/issues/315)) ([ca3deb4](https://github.com/mctlhq/mctl-telegram/commit/ca3deb48b2936209f8261a9af1e3eb2a39c9e105))
* **agent:** headless worker for the communication agent (A-PR8, Option C) ([#308](https://github.com/mctlhq/mctl-telegram/issues/308)) ([98b338e](https://github.com/mctlhq/mctl-telegram/commit/98b338ecfb0e98d341bef89ca537b5e4daa50fe4))
* **agents:** add opt-in flag for auto-fetching media ([#295](https://github.com/mctlhq/mctl-telegram/issues/295)) ([f2d8cce](https://github.com/mctlhq/mctl-telegram/commit/f2d8ccea46cd2b1f2f07b92d47671f71da692525))
* **agent:** saved-messages control plane, executor, owner profile (A-PR7) ([#307](https://github.com/mctlhq/mctl-telegram/issues/307)) ([33311bf](https://github.com/mctlhq/mctl-telegram/commit/33311bf1ab3cccff3c58f676d3b427e3ee8343e0))
* **agent:** store tenant owner profiles encrypted ([#328](https://github.com/mctlhq/mctl-telegram/issues/328)) ([061933b](https://github.com/mctlhq/mctl-telegram/commit/061933b261410bc45aa85ed57930814ceaaf94ab))
* **docker:** add dedicated agent-worker runtime image ([#313](https://github.com/mctlhq/mctl-telegram/issues/313)) ([afe5823](https://github.com/mctlhq/mctl-telegram/commit/afe58231f2aa64b95808aeb43f35717f096caaff))


### Bug Fixes

* **agent-worker:** bind the health listener synchronously, not on a timer ([#314](https://github.com/mctlhq/mctl-telegram/issues/314)) ([cdadc2c](https://github.com/mctlhq/mctl-telegram/commit/cdadc2cf993cbb2661899407f8f7753d1e03529e))
* **agent-worker:** suppress adversarial prompt echoes ([c5900eb](https://github.com/mctlhq/mctl-telegram/commit/c5900eb2f1c0c912fc3d56f36e5b1f386eaf806d))
* **agent-worker:** suppress adversarial prompt echoes ([ddc1686](https://github.com/mctlhq/mctl-telegram/commit/ddc1686c8c2021fe5d1376feb7b173805892041f))
* **agent:** bind job completion to durable result ([#331](https://github.com/mctlhq/mctl-telegram/issues/331)) ([c2fcf32](https://github.com/mctlhq/mctl-telegram/commit/c2fcf327e1328b405c83a52ab97d50a7fb290d59))
* **agent:** claim jobs with POST ([#327](https://github.com/mctlhq/mctl-telegram/issues/327)) ([314b759](https://github.com/mctlhq/mctl-telegram/commit/314b759c6ef71997896ed6c4141c0ff665945c1d))
* **agent:** close remaining policy gaps and sent-marker gap from [#290](https://github.com/mctlhq/mctl-telegram/issues/290)/[#299](https://github.com/mctlhq/mctl-telegram/issues/299) ([#304](https://github.com/mctlhq/mctl-telegram/issues/304)) ([cb544ce](https://github.com/mctlhq/mctl-telegram/commit/cb544cecda3e0d5aa80511e9faa9e15d8f37042f))
* **agent:** poll Saved Messages commands from history ([#319](https://github.com/mctlhq/mctl-telegram/issues/319)) ([c66ae91](https://github.com/mctlhq/mctl-telegram/commit/c66ae9168fba0a54b2e5ec7070199fc4d87938dc))
* **agent:** protect approval codes at rest ([#326](https://github.com/mctlhq/mctl-telegram/issues/326)) ([54f0aab](https://github.com/mctlhq/mctl-telegram/commit/54f0aabf26baed84729898734d74ee080a83c85a))
* **agent:** saved-history poller must not gate on msg.Out ([#322](https://github.com/mctlhq/mctl-telegram/issues/322)) ([ea04c8f](https://github.com/mctlhq/mctl-telegram/commit/ea04c8fd387e87fc993a91a86dea0db58936e31f))
* **agent:** verify durable MCP job completion ([#316](https://github.com/mctlhq/mctl-telegram/issues/316)) ([d92939d](https://github.com/mctlhq/mctl-telegram/commit/d92939dcafa68bce70f0dd99f7deaa87245e95e1))
* **ci:** dedupe claude-review runs and drop blind fallback retry ([#309](https://github.com/mctlhq/mctl-telegram/issues/309)) ([e9e3db1](https://github.com/mctlhq/mctl-telegram/commit/e9e3db1c6bc2d9ecad61437ff71390ff965e7f1f))
* **ci:** fail incomplete Claude reviews ([#323](https://github.com/mctlhq/mctl-telegram/issues/323)) ([2acc457](https://github.com/mctlhq/mctl-telegram/commit/2acc457baab81439e95249d7a0ad1c929116cc32))
* **ci:** preserve zero diff-line count in Claude review ([#291](https://github.com/mctlhq/mctl-telegram/issues/291)) ([5133a87](https://github.com/mctlhq/mctl-telegram/commit/5133a87d734cf5c2932096cfca1cbb5e7838fea3))
* **db:** add job_leads.job_id via idempotent ALTER, not inline CREATE TABLE ([#310](https://github.com/mctlhq/mctl-telegram/issues/310)) ([e4e7928](https://github.com/mctlhq/mctl-telegram/commit/e4e792857ea8a441183ac376d9cbbc0370d2cf45))
* **oauth:** recover refresh-token rotation races instead of failing them ([#343](https://github.com/mctlhq/mctl-telegram/issues/343)) ([355cb96](https://github.com/mctlhq/mctl-telegram/commit/355cb965b37795957fabc3060b54d4dab48f3bbf))
* **telegram:** retire duplicated auth sessions ([#324](https://github.com/mctlhq/mctl-telegram/issues/324)) ([0438490](https://github.com/mctlhq/mctl-telegram/commit/0438490d2e2bbf680e2891dce997ec2637378502))

## [0.44.1](https://github.com/mctlhq/mctl-telegram/compare/0.44.0...0.44.1) (2026-07-20)


### Bug Fixes

* **web:** align landing privacy claims with agent storage ([#301](https://github.com/mctlhq/mctl-telegram/issues/301)) ([e7662e1](https://github.com/mctlhq/mctl-telegram/commit/e7662e13680c64a80a2c56442755426060359a03))

## [0.44.0](https://github.com/mctlhq/mctl-telegram/compare/0.43.0...0.44.0) (2026-07-20)


### Features

* add edit, delete, forward, search, and react message tools ([cf6ba2d](https://github.com/mctlhq/mctl-telegram/commit/cf6ba2d5dd392f6376fcddc0045e01c883e0436a))
* **agent:** add server-side policy engine ([#290](https://github.com/mctlhq/mctl-telegram/issues/290)) ([edbf4aa](https://github.com/mctlhq/mctl-telegram/commit/edbf4aa0cc4f4b0e70bfe1c580a7e6be115c6cd1))
* **agent:** incoming update listener ([#299](https://github.com/mctlhq/mctl-telegram/issues/299)) ([c48559f](https://github.com/mctlhq/mctl-telegram/commit/c48559f9b55fdb838a0479d3a95f7e3f65982575))
* **agents:** issue-282-get-media-single-shot-confirmation-consu ([af7a024](https://github.com/mctlhq/mctl-telegram/commit/af7a024522f23896735be98cdc91a76aad8718ff))
* **agents:** issue-287-add-send-media-mcp-tool-for-photo-video ([#293](https://github.com/mctlhq/mctl-telegram/issues/293)) ([c8ce74e](https://github.com/mctlhq/mctl-telegram/commit/c8ce74ed7db76149e57a1c5b871665ab53d4b50d))
* **db:** agent domain schema and repos for the communication agent ([#286](https://github.com/mctlhq/mctl-telegram/issues/286)) ([4d574ec](https://github.com/mctlhq/mctl-telegram/commit/4d574ecdb05069bb41bd0fd22e2d4fb9485bafa4))
* **db:** durable agent job queue with claim, retry, and dead-letter ([#288](https://github.com/mctlhq/mctl-telegram/issues/288)) ([d124c00](https://github.com/mctlhq/mctl-telegram/commit/d124c00dbfdca9eef9af9f17f625f241ec21bec7))
* **telegram:** pinned pool entries with agent update handlers ([#289](https://github.com/mctlhq/mctl-telegram/issues/289)) ([4b01a56](https://github.com/mctlhq/mctl-telegram/commit/4b01a5623838b971333e753f79bd86273eb0b6c1))
* **web:** reorient landing for non-technical users ([cde493f](https://github.com/mctlhq/mctl-telegram/commit/cde493fb99c397f7fafbe81f450e82b67fbb18f2))


### Bug Fixes

* **local-bridge:** defer get_media confirmation teardown until download completes ([6b27897](https://github.com/mctlhq/mctl-telegram/commit/6b27897f990590a273ca69dfe2f04da71959753f))
* **mcp:** collapse expired-identity leak, skip in-flight in sweep, delete stale media refs ([d697c19](https://github.com/mctlhq/mctl-telegram/commit/d697c19d9ed9f9602023d086d2aed341a293ded7))
* **mcp:** defer get_media confirmation teardown until download completes ([b72a88b](https://github.com/mctlhq/mctl-telegram/commit/b72a88bd3db846a1ffdb63f68ce1564a1213727f))
* **mcp:** make Claim's in-flight check win over expiry, burn token on wrong-user/mismatch ([4bda81e](https://github.com/mctlhq/mctl-telegram/commit/4bda81ee83f31dec7142274297a7e3ed3872b60a))
* **mcp:** survive cancellation on get_media, classify wrong-user during in-flight ([fbdbbbe](https://github.com/mctlhq/mctl-telegram/commit/fbdbbbe4b1ed22fce01a49c60c490ff9d3def3a1))
* **mcp:** verify peer ownership before non-channel delete, cost forward rate-limit by batch size ([60b6422](https://github.com/mctlhq/mctl-telegram/commit/60b6422ff938e37aa880bfd2a3d452c302f072bb))
* **oauth:** auto-persist tier=client to DB on sign-in when AUTO_APPROVE_CLIENTS=true ([0083bea](https://github.com/mctlhq/mctl-telegram/commit/0083beab909f3a6b9968a11cb4615f0949878b9b))
* **oauth:** make GetAccessTier best-effort, add DB materialization tests ([01d0338](https://github.com/mctlhq/mctl-telegram/commit/01d03387ea5357c2b18f894cc89aabd580276551))

## [0.43.0](https://github.com/mctlhq/mctl-telegram/compare/0.42.0...0.43.0) (2026-07-14)


### Features

* **telegram:** add before_id pagination to get_messages with a raw-page cursor ([#280](https://github.com/mctlhq/mctl-telegram/issues/280)) ([1f1dcad](https://github.com/mctlhq/mctl-telegram/commit/1f1dcadaff1efc7ff80ee4d4e70f183c6e7385c4))
* **telegram:** surface media metadata and add prepare_get_media/get_media tools ([#279](https://github.com/mctlhq/mctl-telegram/issues/279)) ([3470292](https://github.com/mctlhq/mctl-telegram/commit/34702923bb8e51c6ccf997a13b3ef47e66e85b61))


### Bug Fixes

* **ci:** detect claude-review SDK failure the outcome field misses ([9452f1a](https://github.com/mctlhq/mctl-telegram/commit/9452f1ae404985a49d985d49077b1b1d00061779))
* **ci:** detect claude-review SDK failure the outcome field misses ([982098c](https://github.com/mctlhq/mctl-telegram/commit/982098ce6b374454957c48306e54d4d659f079b5))
* **ci:** upgrade Go toolchain to 1.26.5 ([fae73e3](https://github.com/mctlhq/mctl-telegram/commit/fae73e3ba2af998e4e15d1b21ad677c75cbbaa51))
* **docs:** address submission accuracy review ([1717631](https://github.com/mctlhq/mctl-telegram/commit/1717631d3aae06153e1d4ca0e22ac1a15765fe1f))

## [0.42.0](https://github.com/mctlhq/mctl-telegram/compare/0.41.2...0.42.0) (2026-07-03)


### Features

* **web:** refresh demo walkthrough ([4071b55](https://github.com/mctlhq/mctl-telegram/commit/4071b555d7d6e8a9270949837ff38fe0b264aa6a))
* **web:** refresh demo walkthrough ([95df6f3](https://github.com/mctlhq/mctl-telegram/commit/95df6f3213ef852ce1b44e79b4f8c3748d01fa12))


### Bug Fixes

* **mcp:** mark admin tool telegram_id/tier params as required ([#272](https://github.com/mctlhq/mctl-telegram/issues/272)) ([0166fca](https://github.com/mctlhq/mctl-telegram/commit/0166fcab3068028c88f550d99251e74e1fad2a24))
* **mcp:** redact telegram login secrets ([98912ab](https://github.com/mctlhq/mctl-telegram/commit/98912abe44b193f307d0e1c167b5904fadba852f))
* **mcp:** redact telegram login secrets ([343cd77](https://github.com/mctlhq/mctl-telegram/commit/343cd770541eb0e5e08d97834d52e1e218b6687b))

## [0.41.2](https://github.com/mctlhq/mctl-telegram/compare/0.41.1...0.41.2) (2026-06-04)


### Bug Fixes

* **mcp:** block disconnect/delete for demo reviewer identity ([#260](https://github.com/mctlhq/mctl-telegram/issues/260)) ([a5a4c3d](https://github.com/mctlhq/mctl-telegram/commit/a5a4c3df86120d8b5a20648ac77184d6a0419ef7))

## [0.41.1](https://github.com/mctlhq/mctl-telegram/compare/0.41.0...0.41.1) (2026-05-30)


### Bug Fixes

* **telegram:** skip min peers when seeding peer cache ([#254](https://github.com/mctlhq/mctl-telegram/issues/254)) ([70e44e2](https://github.com/mctlhq/mctl-telegram/commit/70e44e2383903286595938ad3e54f9a38e5e8573))

## [0.41.0](https://github.com/mctlhq/mctl-telegram/compare/0.40.0...0.41.0) (2026-05-30)


### Features

* add fileutil.Allowed path sandbox guard ([5fed725](https://github.com/mctlhq/mctl-telegram/commit/5fed7253620e3b4f8639c66a50e32a48f61e7f2c))
* add MCP_TOOL_FILTER env var to expose only read-only tools ([2cc30c7](https://github.com/mctlhq/mctl-telegram/commit/2cc30c71fde551afd108127dc0314a5e4657cffd))
* add QR code login to cmd/login via --qr flag ([1e4af94](https://github.com/mctlhq/mctl-telegram/commit/1e4af947c837167d3b3e55c529d14ac3c9b7df3f))
* **mcp:** add connected_via to list_telegram_identities ([3de32fd](https://github.com/mctlhq/mctl-telegram/commit/3de32fd4faeaa5879a68c1b53e696d484e2ff5e4))
* **mcp:** add Origin-header validation and Claude connector submission prep ([b687bfd](https://github.com/mctlhq/mctl-telegram/commit/b687bfdd422998b4afb13adf6be94bbebe796e03))
* **mcp:** mark user read tools readOnly for Claude auto-permissions ([4b707d4](https://github.com/mctlhq/mctl-telegram/commit/4b707d4d02d3b1d404f03f10a8b40c8022032571))
* sanitize Telegram message content before MCP wrapping ([606b762](https://github.com/mctlhq/mctl-telegram/commit/606b762f529545b351293fea980a14b1bb4c181c))
* **telegram:** add api_id-wide rate limit and login floodwait ([f341f6f](https://github.com/mctlhq/mctl-telegram/commit/f341f6f8742cc89ab17926eeb5bce560bf46325d))
* **ui:** polish frontend — SVG icons, hero glow, entrance animations ([6036d97](https://github.com/mctlhq/mctl-telegram/commit/6036d97f92d124d4f7ac9706b2fd1516b0c3104e))


### Bug Fixes

* **auth:** remove telegram:bot_access scope from OIDC login ([6d38cd9](https://github.com/mctlhq/mctl-telegram/commit/6d38cd913ff5a8132725eea13253f60306037c5b))
* **config:** address P3 review nits on OriginGuard ([6401be0](https://github.com/mctlhq/mctl-telegram/commit/6401be0db237a343fa5f798f00af7d320010aae3))
* **db:** add migration for oauth_refresh_tokens.client_name; test revoked token ([5ae4f72](https://github.com/mctlhq/mctl-telegram/commit/5ae4f72d810bcb71b109a6a3841162b9c166c225))
* **db:** denormalize client_name onto oauth_refresh_tokens; add connected_via test ([3cb136e](https://github.com/mctlhq/mctl-telegram/commit/3cb136ee18f2d77a3954e0ae27cdb53cd1b94c04))
* **fileutil:** deny broken symlinks in Allowed path sandbox ([182abeb](https://github.com/mctlhq/mctl-telegram/commit/182abeb99536be22c9078bb41a80ee374968515f))
* **fileutil:** deny intermediate broken symlinks in realPath parent-walk loop ([41b4f82](https://github.com/mctlhq/mctl-telegram/commit/41b4f82c1f33a30d0a81ff97ee78e9537f938ac1))
* **fileutil:** skip empty-string roots to prevent silent CWD expansion ([d2f6388](https://github.com/mctlhq/mctl-telegram/commit/d2f638893b19ef9ee996c117591549b8878d17d0))
* **login:** wire Migrate callback and reject --phone+--qr combination ([bc70eaf](https://github.com/mctlhq/mctl-telegram/commit/bc70eaf01c7aa9b0703e55d564cfec23d3c700e0))
* **mcp:** guard From and PeerTitle against [empty] sentinel in wrapMessages ([4b572d1](https://github.com/mctlhq/mctl-telegram/commit/4b572d192e403a7464291e97585c4cfb8f0b4920))
* **mcp:** mark admin read tools readOnly; sync submission artifacts ([#251](https://github.com/mctlhq/mctl-telegram/issues/251)) ([1eb6884](https://github.com/mctlhq/mctl-telegram/commit/1eb68846bbf189fd1fba2402b6f3a8461c74fa78))
* **mcp:** preserve empty text for media-only messages in wrapMessages ([8a8104d](https://github.com/mctlhq/mctl-telegram/commit/8a8104da44c179f964016131fed69e3fc718bf36))
* **metrics:** forward WriteHeader only once to avoid superfluous call ([f8caac9](https://github.com/mctlhq/mctl-telegram/commit/f8caac9f9e44853ee86a2c6805567f812926eaeb))
* **oauth:** show success interstitial after connect instead of bare 302 ([00e228d](https://github.com/mctlhq/mctl-telegram/commit/00e228d09693221c98376dd2f3d29a218f24b65c))
* **oauth:** tighten connect app-name host match + log issuer parse failure ([8918824](https://github.com/mctlhq/mctl-telegram/commit/891882437c39e6f4ef988090c884b168b8fb1b56))
* **telegram:** seed peer cache from dialogs to fix get_messages PEER_ID_INVALID ([e6eaa59](https://github.com/mctlhq/mctl-telegram/commit/e6eaa593d0516b2dab0e48ed256e74d068c57cd2))
* **telegram:** skip zero-AccessHash entities when seeding peer cache ([b8c873d](https://github.com/mctlhq/mctl-telegram/commit/b8c873d181ebde7aa17ce7b6ee39af8487688c3d))
* **ui:** add prefers-reduced-motion guard for entrance animations ([273fd3a](https://github.com/mctlhq/mctl-telegram/commit/273fd3aba090eec4be4ea0aad2548cf2e18cee0f))

## [0.40.0](https://github.com/mctlhq/mctl-telegram/compare/0.39.0...0.40.0) (2026-05-26)


### Features

* **mcp:** explicit tool annotations + ChatGPT Apps submission readiness ([a121f5a](https://github.com/mctlhq/mctl-telegram/commit/a121f5af7fdee5f4c33eff5899e0fb54627d8ee3))
* **mcp:** explicit tool annotations and ChatGPT Apps submission readiness ([d59c45a](https://github.com/mctlhq/mctl-telegram/commit/d59c45a2076329a87803fa5eeee4eef4777ea0e7))

## [0.39.0](https://github.com/mctlhq/mctl-telegram/compare/0.38.2...0.39.0) (2026-05-25)


### Features

* **telegram:** bound login RPCs and instrument the SendCode step ([6273c78](https://github.com/mctlhq/mctl-telegram/commit/6273c78183a726b008e74e0794b4ec2c71ff6163))
* **telegram:** bound login RPCs and instrument the SendCode step ([d4a4ae5](https://github.com/mctlhq/mctl-telegram/commit/d4a4ae59f5b5aa6e829f7165c6d65269c9a955c4))


### Bug Fixes

* **oauth:** classify per-RPC deadline as timeout so the stall alert fires ([0e6e196](https://github.com/mctlhq/mctl-telegram/commit/0e6e196606661e517f3f9fe8c270103875806e20))

## [0.38.2](https://github.com/mctlhq/mctl-telegram/compare/0.38.1...0.38.2) (2026-05-25)


### Bug Fixes

* **oauth:** log telegram login outcome and raise send-code wait to 90s ([15da019](https://github.com/mctlhq/mctl-telegram/commit/15da0197292047645d22549d2067568b6e89d22c))
* **oauth:** log telegram login outcome and raise send-code wait to 90s ([285b1cb](https://github.com/mctlhq/mctl-telegram/commit/285b1cb377448989c8a4048742bed4d1408cb807))

## [0.38.1](https://github.com/mctlhq/mctl-telegram/compare/0.38.0...0.38.1) (2026-05-25)


### Bug Fixes

* **oauth:** don't reset es.step when a duplicate code/password submit races ([4343645](https://github.com/mctlhq/mctl-telegram/commit/4343645edc1f172cfd806f2a162d187cb2aaaa83))
* **oauth:** guard handleEnableStart against duplicate /start cancelling live flow ([ef27626](https://github.com/mctlhq/mctl-telegram/commit/ef276269061219897ff7b150c442876bcad3f83c))
* **oauth:** recover from concurrent enable-step submits instead of dead-ending ([00e2683](https://github.com/mctlhq/mctl-telegram/commit/00e2683eee7e708f8ceb9f0f6afdc624c42c0bdf))
* **oauth:** recover from concurrent enable-step submits instead of dead-ending ([1f9995c](https://github.com/mctlhq/mctl-telegram/commit/1f9995cdc0f31127f6aa24b797dbef8031e4668f))

## [0.38.0](https://github.com/mctlhq/mctl-telegram/compare/0.37.2...0.38.0) (2026-05-25)


### Features

* **agents:** issue-202-mctl-telegram-canary-cronjob-stuck-on-im ([#211](https://github.com/mctlhq/mctl-telegram/issues/211)) ([9d77c82](https://github.com/mctlhq/mctl-telegram/commit/9d77c826b90b9cc610d653b8ac83208f6d4d0ae5))

## [0.37.2](https://github.com/mctlhq/mctl-telegram/compare/0.37.1...0.37.2) (2026-05-25)


### Features

* **web:** refresh /demo walkthrough video (full 8-step run) ([51cab8c](https://github.com/mctlhq/mctl-telegram/commit/51cab8cef21db9d2008bcdbc8b86631f558695f7))
* **web:** refresh /demo walkthrough video (full 8-step run) ([a86cde1](https://github.com/mctlhq/mctl-telegram/commit/a86cde1691c2e142539ac10a4e8832912b3353c0))


### Miscellaneous Chores

* force release for refreshed /demo walkthrough video ([829d55a](https://github.com/mctlhq/mctl-telegram/commit/829d55aeb91d7a895551a7ab6dd5739cfc8c5f64))

## [0.37.1](https://github.com/mctlhq/mctl-telegram/compare/0.37.0...0.37.1) (2026-05-25)


### Miscellaneous Chores

* release 0.37.1 ([56a0446](https://github.com/mctlhq/mctl-telegram/commit/56a0446c1fb82713d09415338a904d3ae960e87f))

## [0.37.0](https://github.com/mctlhq/mctl-telegram/compare/0.36.0...0.37.0) (2026-05-25)


### Features

* **web:** serve demo walkthrough video on /demo ([fa5c498](https://github.com/mctlhq/mctl-telegram/commit/fa5c498ccc51e947f3fe81538c1d4b0dd18ce6aa))
* **web:** serve demo walkthrough video on /demo ([1d9085d](https://github.com/mctlhq/mctl-telegram/commit/1d9085d60b881cb63c598a5816ca3200ddecccb7))

## [0.36.0](https://github.com/mctlhq/mctl-telegram/compare/0.35.1...0.36.0) (2026-05-25)


### Features

* **mcp:** force dry-run for reviewer/demo account sends ([ecc3459](https://github.com/mctlhq/mctl-telegram/commit/ecc345946e3e2e1a82c5bc47c188f636efdfe124))
* **mcp:** force dry-run for the reviewer/demo account's sends ([8b10a4d](https://github.com/mctlhq/mctl-telegram/commit/8b10a4da1ec76439abb70ff5eb66fac3b222fb38))

## [0.35.1](https://github.com/mctlhq/mctl-telegram/compare/0.35.0...0.35.1) (2026-05-24)


### Bug Fixes

* **oauth:** allow cross-origin redirect after sign-in (CSP form-action) ([8d4dabc](https://github.com/mctlhq/mctl-telegram/commit/8d4dabcbec3f0da4016ed4d3113f0d5988b725af))
* **oauth:** allow cross-origin redirect after sign-in (CSP form-action) ([080e6a8](https://github.com/mctlhq/mctl-telegram/commit/080e6a834f3f93449025e69fc2d123558fa4d5fb))

## [0.35.0](https://github.com/mctlhq/mctl-telegram/compare/0.34.1...0.35.0) (2026-05-24)


### Features

* **oauth:** add password-gated reviewer/demo auth-mode ([e15a552](https://github.com/mctlhq/mctl-telegram/commit/e15a5522aeed726b8cf8ef3ac95f289a68884be6))
* **oauth:** password-gated reviewer/demo auth-mode ([de12127](https://github.com/mctlhq/mctl-telegram/commit/de12127634d76daec9b9c4cdbe0e96035028c8c5))


### Bug Fixes

* **oauth:** harden demo reviewer login per review ([d33ac80](https://github.com/mctlhq/mctl-telegram/commit/d33ac806629fa6616cfe2da164a1068978fd8802))

## [0.34.1](https://github.com/mctlhq/mctl-telegram/compare/0.34.0...0.34.1) (2026-05-24)


### Bug Fixes

* **ui:** tidy footer layout on mobile ([2009448](https://github.com/mctlhq/mctl-telegram/commit/20094485391410ba452d3d4b70634b87721e6a9e))
* **ui:** tidy footer layout on mobile ([48cd8dc](https://github.com/mctlhq/mctl-telegram/commit/48cd8dc4fed5333bfa2ad876073c7833bcc0fc59))

## [0.34.0](https://github.com/mctlhq/mctl-telegram/compare/0.33.0...0.34.0) (2026-05-24)


### Features

* **ui:** add demo link to topbar nav ([9c3bae0](https://github.com/mctlhq/mctl-telegram/commit/9c3bae0248c85ba9123aa077a5896549b6006f76))
* **ui:** add demo link to topbar nav ([2e773f0](https://github.com/mctlhq/mctl-telegram/commit/2e773f01d569154006863ddc1f572456cd890f27))

## [0.33.0](https://github.com/mctlhq/mctl-telegram/compare/0.32.0...0.33.0) (2026-05-24)


### Features

* **web:** add /demo page for ChatGPT App review recording ([43f5a94](https://github.com/mctlhq/mctl-telegram/commit/43f5a9487fa7a1a40f80d85614bdfe190c9723fc))
* **web:** add /demo page for ChatGPT App review recording ([aeefd00](https://github.com/mctlhq/mctl-telegram/commit/aeefd0008a8252eaca1f0fbf41d84565c0f1e7e7))

## [0.32.0](https://github.com/mctlhq/mctl-telegram/compare/0.31.0...0.32.0) (2026-05-24)


### Features

* **mcp:** add outputSchema to all MCP tool descriptors ([25d9c22](https://github.com/mctlhq/mctl-telegram/commit/25d9c2219e35a414c1861af592122a3520c5a3fc))
* **mcp:** add outputSchema to tool descriptors ([8f2efdd](https://github.com/mctlhq/mctl-telegram/commit/8f2efdd0a5e745896900cc8cf531876f706b9f3c))

## [0.31.0](https://github.com/mctlhq/mctl-telegram/compare/0.30.6...0.31.0) (2026-05-24)


### Features

* **web:** add /terms terms-of-service page ([5e7f0b1](https://github.com/mctlhq/mctl-telegram/commit/5e7f0b1413db4ec103a1afce0ff9df57aac41a16))
* **web:** serve OpenAI Apps domain-verification token ([5f102bf](https://github.com/mctlhq/mctl-telegram/commit/5f102bf1152a1d1f3172a6eb1bf61d0df4ea0188))


### Bug Fixes

* **mcp:** mark Telegram-reading tools as open-world ([d1d69a7](https://github.com/mctlhq/mctl-telegram/commit/d1d69a779820593b53031d9346067ef80ec02183))
* **oauth:** raise authorize state cap to 4096 for OpenAI Apps relay ([41b1f37](https://github.com/mctlhq/mctl-telegram/commit/41b1f37d735da360e57e026dfb070938753bda17))

## [0.30.6](https://github.com/mctlhq/mctl-telegram/compare/0.30.5...0.30.6) (2026-05-23)


### Bug Fixes

* **mcp:** annotate send_message as destructive/open-world for submission ([c7a8bcc](https://github.com/mctlhq/mctl-telegram/commit/c7a8bcc5e6f0e72173a051d4e20b510e300227f7))
* **mcp:** annotate send_message as destructive/open-world for submission ([56f8864](https://github.com/mctlhq/mctl-telegram/commit/56f886450b06d4bd00149f897df2be71f88aec6a))

## [0.30.5](https://github.com/mctlhq/mctl-telegram/compare/0.30.4...0.30.5) (2026-05-23)


### Bug Fixes

* **web:** reorder CTA buttons — install actions first, Copy MCP URL after ([1105240](https://github.com/mctlhq/mctl-telegram/commit/1105240c88713e0ccc50cae0bcf05eab999d21a6))

## [0.30.4](https://github.com/mctlhq/mctl-telegram/compare/0.30.3...0.30.4) (2026-05-23)


### Bug Fixes

* **send:** preserve draft-preview contract, fix bridge propagation ([93fd781](https://github.com/mctlhq/mctl-telegram/commit/93fd7817f1250a4501f62e98f094e9dbb10ff1cd))
* **send:** preserve draft-preview contract, fix bridge propagation ([23ba8a1](https://github.com/mctlhq/mctl-telegram/commit/23ba8a1a3884c71502a183f34280cec79d6b37e7))
* set destructiveHint=false and openWorldHint=false on send_message ([877d0e0](https://github.com/mctlhq/mctl-telegram/commit/877d0e04e293c32011c22edcedc2e97e4292e016))

## [0.30.3](https://github.com/mctlhq/mctl-telegram/compare/0.30.2...0.30.3) (2026-05-23)


### Bug Fixes

* **mcp:** correct tool annotation hints for ChatGPT App submission ([700ac53](https://github.com/mctlhq/mctl-telegram/commit/700ac530037ca9c6a945ec29c8b16900655658a9))
* **mcp:** correct tool annotation hints for ChatGPT App submission ([929d6dd](https://github.com/mctlhq/mctl-telegram/commit/929d6dd4ee2ea64dc9831224dc66f282c8421a2f))
* remove mode=draft from send_message — always send for real ([3f66f8b](https://github.com/mctlhq/mctl-telegram/commit/3f66f8b03188df49e246b8fa65f62cf5f8ce670b))

## [0.30.2](https://github.com/mctlhq/mctl-telegram/compare/0.30.1...0.30.2) (2026-05-23)


### Bug Fixes

* remove prepare_send_message to fix mobile ChatGPT send stall ([c19f73e](https://github.com/mctlhq/mctl-telegram/commit/c19f73e8f126cb62a511ea5184eeebebf0c558f2))
* remove prepare_send_message to fix mobile ChatGPT send stall ([273d903](https://github.com/mctlhq/mctl-telegram/commit/273d9035b657ed73705267ae7588ebc97468bb0b))

## [0.30.1](https://github.com/mctlhq/mctl-telegram/compare/0.30.0...0.30.1) (2026-05-23)


### Bug Fixes

* address review on set_account_send + TTL drift ([9bc70e0](https://github.com/mctlhq/mctl-telegram/commit/9bc70e0e7ccf0e1362fa6072771538e263d7076a))
* send-by-default connect + ChatGPT prepare/send flow ([88ea49b](https://github.com/mctlhq/mctl-telegram/commit/88ea49bfe3ffa3b287943b418f67e521773319d8))
* send-by-default connect + ChatGPT prepare/send flow ([39c00ae](https://github.com/mctlhq/mctl-telegram/commit/39c00ae9fd41b09a9597d74b9385f4179a34ec8f))

## [0.30.0](https://github.com/mctlhq/mctl-telegram/compare/0.29.4...0.30.0) (2026-05-23)


### Features

* **agents:** issue-154-nav-replace-github-text-link-with-a-gith ([577eb84](https://github.com/mctlhq/mctl-telegram/commit/577eb843febfad08b3483f54a04a4fd5fda0c44e))
* **agents:** issue-158-non-deterministic-safety-block-on-get-me ([#162](https://github.com/mctlhq/mctl-telegram/issues/162)) ([72ab309](https://github.com/mctlhq/mctl-telegram/commit/72ab309d45998206220c683e9170c06e70bc5a6a))
* **agents:** issue-159-live-send-unusable-when-prepare-send-mes ([63f433d](https://github.com/mctlhq/mctl-telegram/commit/63f433db8a04a3ea6743b93283bc1caf3292026f))
* **mcp:** re-introduce prepare_send_message as read-only tool ([fae8e93](https://github.com/mctlhq/mctl-telegram/commit/fae8e93a06fa93ee83c33cb12678f22d180ca466))
* **ui:** replace GitHub text link with inline SVG icon in topbar ([2568a30](https://github.com/mctlhq/mctl-telegram/commit/2568a3018c51498b27cd24ef91541598c84c1617))


### Bug Fixes

* **docs:** audit-log retention sweeper ships, not planned ([#164](https://github.com/mctlhq/mctl-telegram/issues/164)) ([82db999](https://github.com/mctlhq/mctl-telegram/commit/82db9995ec3d214077c8cced84ba998926225f46))
* **docs:** mark Local Bridge mode as beta-available in ROADMAP ([#151](https://github.com/mctlhq/mctl-telegram/issues/151)) ([545ac17](https://github.com/mctlhq/mctl-telegram/commit/545ac171dc9267a3bfd848a6ee5c73074d8e86ab))
* **ui:** add .gh-link rule to align nav GitHub icon ([30e129f](https://github.com/mctlhq/mctl-telegram/commit/30e129fbe1cfdb626122dc6e4bfd7068928124ff))

## [0.29.4](https://github.com/mctlhq/mctl-telegram/compare/0.29.3...0.29.4) (2026-05-22)


### Bug Fixes

* address P3 nits from review ([212535a](https://github.com/mctlhq/mctl-telegram/commit/212535a9d85f7f30f6268017a04f887c41d031ec))
* change send_message default mode from draft to send ([24cfa06](https://github.com/mctlhq/mctl-telegram/commit/24cfa06b5dc27f7acc0b60a5ef6b5b5dc5f19ab8))
* change send_message default mode from draft to send ([67e18a2](https://github.com/mctlhq/mctl-telegram/commit/67e18a2e189568451c4b962ae225720a480a08cc))

## [0.29.3](https://github.com/mctlhq/mctl-telegram/compare/0.29.2...0.29.3) (2026-05-22)


### Bug Fixes

* remove destructiveHint from send_message for ChatGPT compatibility ([d7db9d8](https://github.com/mctlhq/mctl-telegram/commit/d7db9d88b00dfa0366845c751d2738e556ab7cd1))
* remove destructiveHint from send_message for ChatGPT compatibility ([5266bad](https://github.com/mctlhq/mctl-telegram/commit/5266badfc477bcee8338758a7e1e1af4f01c1f54))

## [0.29.2](https://github.com/mctlhq/mctl-telegram/compare/0.29.1...0.29.2) (2026-05-22)


### Bug Fixes

* **mcp:** address P2/P3 review findings ([76fc59c](https://github.com/mctlhq/mctl-telegram/commit/76fc59c0b0f1db8103f9e024478d2b70e16137d0))
* **mcp:** address remaining P2/P3 review findings ([f88f192](https://github.com/mctlhq/mctl-telegram/commit/f88f192b4977ed6d2549454fbc68dab2a13dbfea))
* **mcp:** remove prepare_send_message tool and raise confirmation TTL to 5m ([e855111](https://github.com/mctlhq/mctl-telegram/commit/e8551112d4bb46df2bc8b27b3353c82797f981ab))
* **mcp:** remove prepare_send_message tool, raise confirmation TTL to 5m ([67370d2](https://github.com/mctlhq/mctl-telegram/commit/67370d288cc846745235e228b306d41243940d51))

## [0.29.1](https://github.com/mctlhq/mctl-telegram/compare/0.29.0...0.29.1) (2026-05-22)


### Bug Fixes

* **mcp:** apply per-peer rate limit on direct send_message path ([59b9aaf](https://github.com/mctlhq/mctl-telegram/commit/59b9aafb199bc8b7944acefff7541db132d441e4))
* **mcp:** extract evaluateDirectSendLimiter and add unit tests ([04f6004](https://github.com/mctlhq/mctl-telegram/commit/04f6004c60db8fefd4b0e9359f21cda20e36179b))
* **mcp:** make confirmation_id optional in send_message ([10ae76c](https://github.com/mctlhq/mctl-telegram/commit/10ae76c2b66e376cdaba2696919b8b6e82133167))
* **mcp:** make confirmation_id optional in send_message ([3e42287](https://github.com/mctlhq/mctl-telegram/commit/3e42287bf0d9f54ce51805df09be33f00d5f9ceb))

## [0.29.0](https://github.com/mctlhq/mctl-telegram/compare/0.28.1...0.29.0) (2026-05-22)


### Features

* **ingress:** Layer-1 sticky routing manifests + acceptance gate ([76825f3](https://github.com/mctlhq/mctl-telegram/commit/76825f3401d685d85224cbb5ce1f22847038edfb))
* **ingress:** Layer-1 sticky routing manifests + acceptance gate ([0a1be8e](https://github.com/mctlhq/mctl-telegram/commit/0a1be8e990e57ae4dcf052031176f90ef15dbf2d))


### Bug Fixes

* **ingress:** plain find() in envoy base64 decoder + harden gate JWT ([78affe1](https://github.com/mctlhq/mctl-telegram/commit/78affe1c12d8f2dbff07b08a6f477a271f327969))

## [0.28.1](https://github.com/mctlhq/mctl-telegram/compare/0.28.0...0.28.1) (2026-05-22)


### Miscellaneous Chores

* release 0.28.1 ([6d67f27](https://github.com/mctlhq/mctl-telegram/commit/6d67f27b8df41289067e7b5cffa073da943d5f6d))

## [0.28.0](https://github.com/mctlhq/mctl-telegram/compare/0.27.0...0.28.0) (2026-05-22)


### Features

* sticky-routing replica-identity observability ([#91](https://github.com/mctlhq/mctl-telegram/issues/91) Layer 2) ([d589cc8](https://github.com/mctlhq/mctl-telegram/commit/d589cc8726dcecf5eb05d82edc8de270418dfa13))


### Bug Fixes

* **bridge,mcp:** clear P3 nits from [#125](https://github.com/mctlhq/mctl-telegram/issues/125) review ([2b54d37](https://github.com/mctlhq/mctl-telegram/commit/2b54d37216297c2aadc1a8419b9404bf606b26ea))

## [0.27.0](https://github.com/mctlhq/mctl-telegram/compare/0.26.2...0.27.0) (2026-05-22)


### Features

* **agents:** issue-94-local-bridge-m4-finish-community-release ([7a6279a](https://github.com/mctlhq/mctl-telegram/commit/7a6279a434c11ea8838d816e948aa541bcad34f9))


### Bug Fixes

* scope privacy page contact to privacy inquiries only ([9d8bce3](https://github.com/mctlhq/mctl-telegram/commit/9d8bce3c4ea5662b23dc90a6cdbcb54a3dd45587))
* topic-specific contact emails on security/privacy ([298f531](https://github.com/mctlhq/mctl-telegram/commit/298f53170b97a957ceab0808cec0c4b32cdf84e7))
* use topic-specific contact emails on security/privacy pages ([75ecf2c](https://github.com/mctlhq/mctl-telegram/commit/75ecf2c5b3b84d9b0ecf47d29d37b2bc1d6e2744))

## [0.26.2](https://github.com/mctlhq/mctl-telegram/compare/0.26.1...0.26.2) (2026-05-22)


### Bug Fixes

* show accent picker on mobile + support@mctl.ai contact ([4953376](https://github.com/mctlhq/mctl-telegram/commit/49533763ec69df9d9c151686d35d4c8ccb4c46b2))
* show accent picker on mobile and use support@mctl.ai contact ([4e5ba55](https://github.com/mctlhq/mctl-telegram/commit/4e5ba554105f839c626cfcf63437f56da7bde9f4))

## [0.26.1](https://github.com/mctlhq/mctl-telegram/compare/0.26.0...0.26.1) (2026-05-22)


### Bug Fixes

* **web:** make all pages mobile-responsive ([eec51ee](https://github.com/mctlhq/mctl-telegram/commit/eec51eef98e84b0051a12435f7ce696d6b50acef))
* **web:** make all pages mobile-responsive ([45f3fdb](https://github.com/mctlhq/mctl-telegram/commit/45f3fdb9efc8ccc436672120ebb973d8bfa84d05))

## [0.26.0](https://github.com/mctlhq/mctl-telegram/compare/0.25.0...0.26.0) (2026-05-22)


### Features

* **web:** restore light/dark theme toggle in shared chrome ([e21d7d8](https://github.com/mctlhq/mctl-telegram/commit/e21d7d863ccaebb87e37e1ea68384f69dd72ef87))
* **web:** restore light/dark theme toggle in shared chrome ([8c91110](https://github.com/mctlhq/mctl-telegram/commit/8c911105884976a791781df3d31f866d3e5b26e0))

## [0.25.0](https://github.com/mctlhq/mctl-telegram/compare/0.24.0...0.25.0) (2026-05-22)


### Features

* **web:** unify visual style across all pages via shared chrome ([6ebc8cf](https://github.com/mctlhq/mctl-telegram/commit/6ebc8cfc8167aeef0327c948eb4d2361eafb9677))
* **web:** unify visual style across all pages via shared chrome ([99d12a3](https://github.com/mctlhq/mctl-telegram/commit/99d12a3976259cb94c5cd919da2f9d8a0df2f00b))


### Bug Fixes

* **metrics:** add 2s/4s latency buckets for SLO p95 accuracy ([de56c7b](https://github.com/mctlhq/mctl-telegram/commit/de56c7bffa1c5231f7241550854934ebc5b687bf))
* **web:** address P3 review nits — stale comment + lite color-scheme ([c7651f1](https://github.com/mctlhq/mctl-telegram/commit/c7651f12d714413d5ac7514a1fc9adbbbd71483c))
* **web:** theme always follows OS, drop stale mctl-theme preference ([2684d8b](https://github.com/mctlhq/mctl-telegram/commit/2684d8b1202dddf5cf4f953a7c997177e923ca81))

## [0.24.0](https://github.com/mctlhq/mctl-telegram/compare/0.23.1...0.24.0) (2026-05-21)


### Features

* add Beta SLOs, burn-rate alerts, and session borrow counter ([f3d6240](https://github.com/mctlhq/mctl-telegram/commit/f3d62400e79eaea2712bcb86af694de2ea953e32))
* add Beta SLOs, burn-rate alerts, and session borrow counter ([#88](https://github.com/mctlhq/mctl-telegram/issues/88)) ([f9e29ce](https://github.com/mctlhq/mctl-telegram/commit/f9e29ce2fb6ecd202d1e225662c3c6b7a9621f63))
* add PrometheusRule manifest for production alerts ([#86](https://github.com/mctlhq/mctl-telegram/issues/86)) ([ec3b116](https://github.com/mctlhq/mctl-telegram/commit/ec3b11687b09125a9f4ecf01e84fecdb8801cb9a))
* **agents:** issue-86-ship-prometheusrule-manifests-for-produc ([e5b61fd](https://github.com/mctlhq/mctl-telegram/commit/e5b61fdd8c42fc6b3b1e57f27c45ec4ab1893eff))
* **agents:** issue-90-beta-capacity-profile-load-test-tuned-co ([d6fd303](https://github.com/mctlhq/mctl-telegram/commit/d6fd303b8c530866aae371d0d8edf74d455a29e1))
* **agents:** issue-92-operational-runbook-for-beta-top-n-incid ([62af604](https://github.com/mctlhq/mctl-telegram/commit/62af6044f738826da0fe09334421c9d0d3ca09d3))
* **db,config:** add configurable DB pool knobs and load-test binary ([ef47b02](https://github.com/mctlhq/mctl-telegram/commit/ef47b02d981479fed1b15077baa95bce050526f5))
* **web:** make landing page LLM-provider agnostic ([4ebc096](https://github.com/mctlhq/mctl-telegram/commit/4ebc0961d8c5cd4bb2aa8b1b1bee33e84750879e))
* **web:** make landing page LLM-provider agnostic ([8058bf4](https://github.com/mctlhq/mctl-telegram/commit/8058bf4804d39edd158284908b091b0eceeeae93))


### Bug Fixes

* **alerts:** add upper-bound guards on warning variants + humanize ([87cd94e](https://github.com/mctlhq/mctl-telegram/commit/87cd94e6f0af01b5f37eab1d496107c0b58e5a96))
* **auth:** unknown AUTH_MODE is now a fatal startup error ([5872cbc](https://github.com/mctlhq/mctl-telegram/commit/5872cbce8beb6d9c597b013f491acaa4cc6833fc))
* **grafana:** coalesce absent error series to zero in SLO panels ([2e992c6](https://github.com/mctlhq/mctl-telegram/commit/2e992c69e2f4c8f5d9c18222c1e15a10c151ef6e))
* **load-test:** count isError results, warn on metrics non-200, delta flood-wait ([060112d](https://github.com/mctlhq/mctl-telegram/commit/060112dbedf512c2049fe2626c5adb76fc174169))
* **load-test:** guard send_message, fix SSE extraction + poller timing ([40f6850](https://github.com/mctlhq/mctl-telegram/commit/40f68504e5c8b6885349f57fa56eb671ae4f96a6))
* **load-test:** MCP initialize handshake + token/draft correctness ([c587f98](https://github.com/mctlhq/mctl-telegram/commit/c587f980dc5b8444cb13a9f73e23c5da69c53b31))
* **oss:** remove internal infra references from SECURITY.md, CLI, issue template ([9b0489d](https://github.com/mctlhq/mctl-telegram/commit/9b0489d3a30b46ef7faef0c8f3a0b71eb2332d2e))
* **oss:** remove internal infra references from SECURITY.md, local CLI, issue template ([10f8034](https://github.com/mctlhq/mctl-telegram/commit/10f80343716f01bc68004a5f40bec5e97cda9dd8))
* point alert runbook_url at existing docs/hpa.md#alerts ([a007129](https://github.com/mctlhq/mctl-telegram/commit/a00712948ed17312a50a68cd0dc01b4676106eeb))
* **web:** address P3 review nits on landing page ([bb917fb](https://github.com/mctlhq/mctl-telegram/commit/bb917fb89fbe11a0bf2d7f192a7d86d482db9c7f))

## [0.23.1](https://github.com/mctlhq/mctl-telegram/compare/0.23.0...0.23.1) (2026-05-21)


### Bug Fixes

* **canary:** address P3 review findings ([f5e6cac](https://github.com/mctlhq/mctl-telegram/commit/f5e6cac0cba4c7c7a19c4c4e889e95e46511008a))
* **canary:** initialize MCP session before tools/call ([11b2795](https://github.com/mctlhq/mctl-telegram/commit/11b2795e6a37417706af354724df0ed3a7f869d1))
* **canary:** initialize MCP session before tools/call ([5f0ca47](https://github.com/mctlhq/mctl-telegram/commit/5f0ca47ad3a9fbf3966282626667a1f06765e07a))
* **web:** remove accent color picker from navbar ([1e13883](https://github.com/mctlhq/mctl-telegram/commit/1e13883285d130b8749e68b2b9668e10bc48c702))

## [0.23.0](https://github.com/mctlhq/mctl-telegram/compare/0.22.0...0.23.0) (2026-05-20)


### Features

* **agents:** issue-87-grafana-dashboard-for-beta-operations ([dbbbd10](https://github.com/mctlhq/mctl-telegram/commit/dbbbd1014e92e72b802813a84c6d204125cf93ca))
* **agents:** issue-93-unified-connect-wizard-oidc-enable-acces ([e3dc686](https://github.com/mctlhq/mctl-telegram/commit/e3dc686820005e099c30d9612519154c6102809c))
* **ops:** add Grafana dashboard for beta operations ([f82f47f](https://github.com/mctlhq/mctl-telegram/commit/f82f47fc18cd2e9a01f0dbf580b0bfca154a094c))
* **web:** unified connect wizard with OIDC permissions step and audit trail ([1afa5da](https://github.com/mctlhq/mctl-telegram/commit/1afa5daef999fbfd50a077dd3cc127ba920daa3e))


### Bug Fixes

* **connect-wizard:** address P1/P2 review findings ([630dc5f](https://github.com/mctlhq/mctl-telegram/commit/630dc5f97d0a3a90aee44ccb37143ab62397cdbf))
* **connect-wizard:** complete wizard step indicator on code and password screens ([3feaa1b](https://github.com/mctlhq/mctl-telegram/commit/3feaa1bd49572653f048506e68372954e50e6bad))
* **connect-wizard:** derive Secure cookie flag + clear cookie on disconnect ([6c1a022](https://github.com/mctlhq/mctl-telegram/commit/6c1a022b1d513f7564d48c378b7aafcfc30e407c))
* **connect-wizard:** preserve wizard mode on empty-code re-render ([1c8ef15](https://github.com/mctlhq/mctl-telegram/commit/1c8ef15001bd62ec3cea891daa94ba69c2317907))
* **connect-wizard:** unblock CI + address P2/P3 review findings ([d3eceb4](https://github.com/mctlhq/mctl-telegram/commit/d3eceb4ae4460a4edbcfc58d6f8d494dc53486c0))
* **grafana:** rename __requires__ to __requires (P1 follow-up) ([ac23e7a](https://github.com/mctlhq/mctl-telegram/commit/ac23e7a3bf56ee2863223ba911b54f50ba77c7e7))
* **grafana:** rename dashboard import key to __inputs (P1 follow-up to [#95](https://github.com/mctlhq/mctl-telegram/issues/95)) ([4717277](https://github.com/mctlhq/mctl-telegram/commit/471727778c57e853cbac59e20877fad7095fd299))
* **grafana:** rename dashboard import key to __inputs (P1 follow-up to [#95](https://github.com/mctlhq/mctl-telegram/issues/95)) ([e096870](https://github.com/mctlhq/mctl-telegram/commit/e09687042c18e9ce0bd9283d242f6190e60e1b3f))

## [0.22.0](https://github.com/mctlhq/mctl-telegram/compare/0.21.0...0.22.0) (2026-05-20)


### Features

* **agents:** issue-67-build-browser-based-telegram-account-onb ([d2826e4](https://github.com/mctlhq/mctl-telegram/commit/d2826e42db4652becadeb16c865d70883e53aa26))
* **agents:** issue-69-improve-mobile-responsiveness-of-tg-mctl ([4c2ccaa](https://github.com/mctlhq/mctl-telegram/commit/4c2ccaa05f871f5b8bb35abe1b7749ffc68b883e))
* **agents:** issue-70-add-user-friendly-error-message-catalog ([dd28a43](https://github.com/mctlhq/mctl-telegram/commit/dd28a43f23b7c746112ff55420f4951ae3828313))


### Bug Fixes

* address P1/P2/P3 review findings in ExchangeConnect and validateClient ([fd85b79](https://github.com/mctlhq/mctl-telegram/commit/fd85b7989ee4fe9cf4d051fbdff49f60bb0191ab))
* **mcp:** swap slog field names: message=rpcErr.Message, code=rpcErr.Code ([6a9b3bb](https://github.com/mctlhq/mctl-telegram/commit/6a9b3bb4b2420c0a849a2f5669635b2cbf8096fa))
* **web:** reorder media queries largest-to-smallest (768→640→480) ([91aa239](https://github.com/mctlhq/mctl-telegram/commit/91aa239896ca5630375b7cf3e8ae5d8517a540e0))

## [0.21.0](https://github.com/mctlhq/mctl-telegram/compare/0.20.1...0.21.0) (2026-05-19)


### Features

* **agents:** issue-68-redesign-tg-mctl-ai-landing-page-for-cli ([1eae213](https://github.com/mctlhq/mctl-telegram/commit/1eae2133f8f504c946b7f36ff3fc262903985cfa))
* **web:** redesign landing page, add /docs route, fix stale auth copy ([9009776](https://github.com/mctlhq/mctl-telegram/commit/9009776e6aef6b087c569d2f9cef9fca3c4e89a8))


### Bug Fixes

* **telegram:** nil-safe SessionStore when Store is nil (test harness) ([61bf4ed](https://github.com/mctlhq/mctl-telegram/commit/61bf4edc5e88001c2c844bc734ca21486f984af1))
* **web:** correct docs.go comment four-&gt;three ([1573fe4](https://github.com/mctlhq/mctl-telegram/commit/1573fe44f7ba8731f9b3c734a9874f1d4657d68a))
* **web:** fix duplicate Telegram bullet in privacy, remove debug comment in landing ([ddf4c12](https://github.com/mctlhq/mctl-telegram/commit/ddf4c129e9cb1f20149f489dddfba9499d8e56cb))

## [0.20.1](https://github.com/mctlhq/mctl-telegram/compare/0.20.0...0.20.1) (2026-05-19)


### Bug Fixes

* **oauth:** drop admin:users from public scopes_supported ([1a2680d](https://github.com/mctlhq/mctl-telegram/commit/1a2680d139521a1d7937cf2b6e9065ccacaa06c7))
* **oauth:** drop admin:users from public scopes_supported ([153beb3](https://github.com/mctlhq/mctl-telegram/commit/153beb312651e1abebba532ca275dca3762f880a))

## [0.20.0](https://github.com/mctlhq/mctl-telegram/compare/0.19.0...0.20.0) (2026-05-19)


### Features

* **agents:** issue-66-scalability-audit-and-hardening-for-100 ([c497eb4](https://github.com/mctlhq/mctl-telegram/commit/c497eb4aaf777cea8431e6a6251dde34b4c04b3c))
* **scalability:** issue-66-scalability-audit-and-hardening-for-100 ([6ddfd1b](https://github.com/mctlhq/mctl-telegram/commit/6ddfd1b0657e0b6bee8194309fbf914bfc6698f1))


### Bug Fixes

* **oauth:** address P1/P2 review findings for DB-backed OAuth paths ([c70319c](https://github.com/mctlhq/mctl-telegram/commit/c70319cf282850638b811711163cc35262925355))
* **oauth:** address P2 findings — FLOOD_PREMIUM_WAIT and evict-insert comment ([e46f0b0](https://github.com/mctlhq/mctl-telegram/commit/e46f0b0a2fc9a38d7d6870108d5e297eff655086))
* **oauth:** fix TOCTOU in Consume* methods and evict live-row mismatch ([79386e7](https://github.com/mctlhq/mctl-telegram/commit/79386e78217a3301d772d974ab985c5fecfe4077))

## [0.19.0](https://github.com/mctlhq/mctl-telegram/compare/0.18.0...0.19.0) (2026-05-19)


### Features

* **oauth:** allow chatgpt.com redirect_uri in implicit-host allowlist ([dea99a8](https://github.com/mctlhq/mctl-telegram/commit/dea99a8d6050f67ffb3dc0ba29d8493fe6362512))
* **oauth:** allow chatgpt.com redirect_uri in implicit-host allowlist ([fbb925f](https://github.com/mctlhq/mctl-telegram/commit/fbb925f1f77391828c3ecf64ca44a097f7f978b0))

## [0.18.0](https://github.com/mctlhq/mctl-telegram/compare/0.17.0...0.18.0) (2026-05-18)


### Features

* **agents:** issue-59-add-observability-and-alerting-for-mctl ([#61](https://github.com/mctlhq/mctl-telegram/issues/61)) ([bb767b1](https://github.com/mctlhq/mctl-telegram/commit/bb767b162d81d4e6cb5151ace65b4021fe7918d5))

## [0.17.0](https://github.com/mctlhq/mctl-telegram/compare/0.16.1...0.17.0) (2026-05-18)


### Bug Fixes

* address codex review on partial-session PR ([4cc0cbc](https://github.com/mctlhq/mctl-telegram/commit/4cc0cbcfd18e23df7de60439636be028c94da599))
* detect unauthorized sessions and log MCP tool calls ([800f45c](https://github.com/mctlhq/mctl-telegram/commit/800f45cf06aaafedf91dbe107c04b34e5a17451a))
* detect unauthorized sessions and log MCP tool calls ([6cc2d83](https://github.com/mctlhq/mctl-telegram/commit/6cc2d83bd312e1bfdcecad908dd56f48ad1599eb))
* distinguish revoked sessions from unfinished ones ([8f21094](https://github.com/mctlhq/mctl-telegram/commit/8f21094ba30c7fcdb75d9ea1fd65c66ce272ef7c))
* **oauth:** clarify 2FA screen and add show-password toggle ([421f8a4](https://github.com/mctlhq/mctl-telegram/commit/421f8a449f958378075bede787ca0dc30896b094))
* **oauth:** clarify 2FA screen and add show-password toggle ([ccde0d1](https://github.com/mctlhq/mctl-telegram/commit/ccde0d1c4625647c2fd328d8158ae0d959e081b8))

## [0.16.1](https://github.com/mctlhq/mctl-telegram/compare/0.16.0...0.16.1) (2026-05-18)


### Bug Fixes

* **oidc:** tolerate Telegram's secp256k1 JWKS key ([#57](https://github.com/mctlhq/mctl-telegram/issues/57)) ([ffa7ede](https://github.com/mctlhq/mctl-telegram/commit/ffa7ede758e94cab72c3aa2beff45126996f05a9))

## [0.16.0](https://github.com/mctlhq/mctl-telegram/compare/0.15.0...0.16.0) (2026-05-18)


### ⚠ BREAKING CHANGES

* **oauth:** requires TELEGRAM_OIDC_CLIENT_ID and TELEGRAM_OIDC_CLIENT_SECRET; TELEGRAM_LOGIN_BOT_USERNAME is removed and TELEGRAM_LOGIN_BOT_TOKEN is now used only for the daily digest. The login bot must have OpenID Connect enabled in BotFather.

### Features

* **auth:** scaffold Telegram OIDC relying party (dormant) ([#54](https://github.com/mctlhq/mctl-telegram/issues/54)) ([e426aab](https://github.com/mctlhq/mctl-telegram/commit/e426aab2e4f23580f6798eb1b54874aeebd99757))
* **oauth:** migrate login from legacy widget to Telegram OIDC ([#56](https://github.com/mctlhq/mctl-telegram/issues/56)) ([5f49593](https://github.com/mctlhq/mctl-telegram/commit/5f49593ab0d6710244770e7d3cb86fcd26a916a3))

## [0.15.0](https://github.com/mctlhq/mctl-telegram/compare/0.14.0...0.15.0) (2026-05-17)


### Features

* **oauth:** add refresh-token grant and dedicate the JWT signing key ([#51](https://github.com/mctlhq/mctl-telegram/issues/51)) ([b255958](https://github.com/mctlhq/mctl-telegram/commit/b255958a53053e7e710631fdf22bdcf2f339eb64))

## [0.14.0](https://github.com/mctlhq/mctl-telegram/compare/0.13.0...0.14.0) (2026-05-17)


### Features

* **web:** redesign landing page on the mctl design system ([#49](https://github.com/mctlhq/mctl-telegram/issues/49)) ([944524f](https://github.com/mctlhq/mctl-telegram/commit/944524fcdecc30b1d823ebd75a1f25f607b8f6d9))

## 0.1.0 (2026-05-13)

### Features

* initial scaffold — Go HTTP server with `/healthz` and `/readyz` returning 200
* multi-stage Dockerfile (golang:1.25-alpine -> alpine:3.20, non-root)
* release-please + centralized mctl-gitops release-deploy wiring
