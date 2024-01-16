# ddWill - packager for a distributed digital will

**Copyright (c) 2021-2024 Caleb L. Power. All rights reserved.**

### What is this?

Okay. So, the use case is this: let's say that you're a company owner or
systems architect, or something like that. You're not dumb, so you're mildly
paranoid about security. You've made it nearly impossible for anyone other
than yourself to get into your stuff.

Neato mosquito. Okay, then you get hit by a bus. Or whatever. People rely on
those system credentials to keep a roof over their heads. So, now we have our
use case: build a system that allows you to securely share your credentials
with people in the event that something happens to you.

### Cool, but how?

I'm glad you asked. Pick several friends that you want to entrust your will or
credentials to. But, make sure to keep the following in mind:

- You probably want to make it a requirement that more than one of your friends
  is required to recover your stuff, yeah? Especially if you and that one
  friend have a falling out or something.
- You also don't want *all* of your friends to be required to recover your
  stuff. Let's face it, if you die early it's probably because you and a friend
  were doing something dumb. If you want a guarantee that your stuff can be
  recovered later, build in some redundancy.
- You probably also want a required master key that you can hide behind a
  website canary or something. You know, something you have to manually update
  every week to prove that you haven't died. And if time expires, it exposes
  the master key.

So, this system will let you build out those files, and it'll let your friends
piece them back together again.

### Obvious disclaimers are obvious.

This ain't production ready, so use it at your own risk.
