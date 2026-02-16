# Changelog

## [0.6.0](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.5.0...v0.6.0) (2026-02-16)


### Features

* add check that domain matches organization ([4ee65c4](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/4ee65c46e15aa3a6029e8b14236d56dcf5089366))
* add initial implementation of account creation ([a2913fd](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/a2913fd96e448bcf2f8e88e399c6bd98a129596f))
* **auth:** use CILogon sub claim as the subject for login tokens ([4b58b82](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/4b58b828852a139962a3a6a6dd5b92ad5344f2f7))
* **comanage:** add update user method ([2a7572e](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/2a7572e7f759387ef5b60692cff578ac44a58971))
* **comanage:** allow adding different types of identifiers ([36ba701](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/36ba701ba2bce6f6c4d8ef23e0febefff88a467d))
* **comanage:** use primary email in profile ([4ff59ea](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/4ff59ea971a9d544ca96d3f367dfe07a31c3fed3))
* create allocations profile during account creation ([7436067](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/7436067bdb27552ed7ceb9764d2ede9fbd29c338))
* **degrees:** add API route for academic degree types ([b50b15f](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/b50b15fe6278598f9c884bcccefa2a9b55e2ea09))
* include existing username in verify OTP response ([fbc3d3a](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/fbc3d3a71039a26aadf6e9b1c38c4890e52bc0c4))
* **models:** update UpdateAccountRequest model ([2cc7366](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/2cc73669c02a3f8a2f1eec96a07773250344778d))
* **otp:** log OTP instead of sending if DEBUG env variable is true ([0fda77d](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/0fda77d22f779060b08e3ea898b8b12d2010ef15))
* require OTP token for creating an account ([5756492](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/575649286a9afbcf4539fb38523002c9d414441b))
* **scripts:** add script for generating development tokens ([ea4b7c8](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/ea4b7c87c9da8ad8e5bc1c55ade6027cd218b60a))
* update identity service during account update ([ee1f030](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/ee1f030005416ca61298d330fdf383e27f5b5c12))


### Bug Fixes

* add missing email when creating identity profile ([edc5cde](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/edc5cde8b0fd2971ebb612447699d328621f899a))
* **cilogon:** fix merge issues ([9964510](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/99645106972467b77e1743210f3386659cd76bf8))
* **config:** add path to FRONTEND_URL ([a14010f](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/a14010ff04ede6e3c51fd648ce25511008be0962))
* fix account creation without an existing identity ([ca41f59](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/ca41f59f0357bb9acdf8d9fde4e1f7f329a3aeff))
* **identity:** fix update if exists behavior ([59b9ed2](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/59b9ed281de29b62746d6ea18fbc428b40034f91))
* **identity:** separate create and update person methods ([c030053](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/c0300537a8e90d37bdded11d0ab73b8f6794d1f1))

## [0.5.0](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.4.1...v0.5.0) (2025-12-23)


### Features

* add CoManage config variables ([52b3267](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/52b3267a7b774bee9b5d288bfa8ea2e3d1b7dca3))
* add initial account response ([302c3b4](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/302c3b4f676671554156df0b454544a71b780bc9))
* add terms and conditions route ([5382b82](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/5382b82e3c02be818d4750e3ad6ecf666c2b1260))
* **auth:** add CILogon client ([96010a6](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/96010a61f7d770f1452bb7d10fa682d4af8c44c6))
* convert bull enrollment script to Python ([a5af642](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/a5af6420487caade36dc68119737deb4375ac661))
* implement identities list ([56a556e](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/56a556eea04211acfa01b884e2e2dc5b727368fd))
* implement SSH key list route ([fa56963](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/fa56963209aec9823fa24d52dc943d8f4b3f3312))


### Bug Fixes

* **comanage:** cast password to a string ([225ad17](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/225ad176ab25204f40b255f1b18045eeca691cf0))
* reenable token requirement for identities route ([d6fe9e9](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/d6fe9e98cae3fd13dad84175243d65d8c3cbe82d))


### Documentation

* **comanage:** fix T and C docstring ([a7f7976](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/a7f7976163bfa61409b4efa6b7c06e76c99cc9a1))

## [0.4.1](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.4.0...v0.4.1) (2025-12-12)


### Bug Fixes

* add missing dependency on fastapi-utilities ([ae3c9f1](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/ae3c9f1ea65d70dce20c12135e381aabe5a256be))

## [0.4.0](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.3.0...v0.4.0) (2025-12-12)


### Features

* store sent OTPs in a SQLite database ([6b03d74](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/6b03d746cb4337698adfc254a734d22b5d1e72a9))

## [0.3.0](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.2.0...v0.3.0) (2025-12-03)


### Features

* send and verify OTPs ([781afc4](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/781afc45de4249389924609a0e7b6e232d64e92f))

## [0.2.0](https://github.com/access-ci-org/ACCESS_Account_Backend/compare/v0.1.0...v0.2.0) (2025-11-19)


### Features

* add CORS middleware ([05c7b22](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/05c7b2245fe4328835aadcaeca1352c687edca39))
* add httpx dependency ([789b567](https://github.com/access-ci-org/ACCESS_Account_Backend/commit/789b56734f6acf675c5b76c38f911d47954a9588))
