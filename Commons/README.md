# Commons
This project contains all the commonly shared code for QuatschAndSuch. The common authentication code can be found in [Authentication](https://github.com/QuatschVirus/QuatschAndSuch/tree/main/Authentication) for now.
## The Cryptography System
The `Crypto` class contains all of the tools required for cryptograpy works. This includes asynchronous encryption using RSA, synchronous enryption using AES, and secure hashing using PBKDF2.
**This project is my first time working with that much cryptography stuff. If there is anything to improve in that regard, please let me know!**
## The Database System
The `Database` class is used to create databases for the other services. It works with Entity Framework and SQLite. Extend it to create a new database model, and add a `DbSet<>` for each table. To correctly map the types to the table, use the Attributes or Fluent API for more complex mappings.
## The Logging System
The `Logger` class represents a custom logging solution to make the logging process slightly less annoying. It is instance-based, and allows you to configure the exact streams the logger writes to. **This is a very bad solution, as it only logs something when it is invoked by code, not exceptions or the likes. I may refactor it in the future to do so, but right now, I'd aprecieate any help with it**
