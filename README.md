# QuatschAndSuch
[![Documentation Status](https://readthedocs.org/projects/quatschandsuch/badge/?version=latest)](https://quatschandsuch.readthedocs.io/en/latest/?badge=latest)  
QuatschAndSuch is an environment, primarily designed towards communication services/apps. In includes a central authentication system using tokens, and all the necessary requirements to easily integrate custom services.

The name is (rather obviously I think) rooted in my common username "QuastchVirus", with Quatschen being german for "Talking nonsense" (or, more colloquially, "Yapping). Y'know, because it's for talking to (most of the time) people.

For more information on the individual services, check out their respective folders.  
For information about how to work with the code base, see the documentation [here](https://quatschandsuch.readthedocs.io/en/latest/)

## The architecture
Currently, all "services" are seperate from another, but can be combined to form a single app. For example, one could combine the Direct Message service ([Slider](https://github.com/QuatschVirus/QuatschAndSuch/tree/main/Slider)) with the (not yet existing) Group Chat service to create essentially a "normal" chat app similar to WhatsApp or the likes. You can aso just make a custom service that is interoparable with the existing systems.

## For the future
I plan to eventually add the following features:
- A group chatting service
- Maybe something along the lines of "server-based" communication (Think Discord, but without DMs)
- End-To-End file sharing
- And much more (if I can think of it)

Open to suggestions!

## Contributions
If you have an idea or a suggestions, feel free! This is open source for a reason. Just make sure to follow the set-out conventions (I'll maybe make an effort to actually define them, for now, just have a look at the code).
I'd be especially grateful for advice or help with databases and secure storage and communiciations, because this is my first ever encounter with actual database systems (SQLite), and my first serious use of encrypted communications and storage.
You can find the associated project [here](https://github.com/users/QuatschVirus/projects/3).
### Contribution Attribution
...
