# Leif's directives — verbatim

The authoritative product intent, in Leif's exact words (typos and all). This is the source of truth;
where my interpretation and his words disagree, his words win. Chronological.

## Cross-machine sync / dev
> revoke the stale phone. Start the mirror so that i can develop it live on my desktop. it has a ce-net dirtory with only the ce repo. i want the ce-net directory to be up to date exactly with this macs ce-net repo

> is ce sync supposed to exist or is that a left over which incorrectly couples systems and a not necessary primitive?

> Alright so when thats done can i start using claude code on my debian at the same time as on my mac and it will be as if its the same machine with the directory constantly in sync

> i dont understand why you ai start thinking that you are in charge. my word is law. We will make it so that it works well for cross machine development at the same time with proper conflict resolution.

> alright right now i want to easily copy and paste text from one machine to the other - how do i do that?

> Why do you build this on top of ce-cast our streaming service?

> Why do we need a domain for mesh tools? why dont we just use the mesh?

> Yes rebuild. we have a lot to do because its not just this - all our apps needs to start using the mesh and be real mesh apps instead of cheating with http

> Fix so that the version always udpates properly! Update the versions to latest everywhere.

> Do it. then make it so that i can work from both of my machines.

> Implement the proper conflict system

> Its dangerous to just write files without proper handling. maybe atuo commit to git or ce-hub and a manual conflict resolution review system?

> I need it to be real time and also easy to monitor changes and we need to be careful about overwrites. But i will work and never think about it - just being able to switch machines during development is awesome.

> But we need git because if one of the devices are shutdown we need to sync and see hat has been done in the mean time

> do b and document a for future

> the ce directory has lots of merge conflicts. use mac as ruler for the ce dir. and none of the e2e scripts are taken over

> We need true realtime. How the fuck is it 5-60s? It must be instant. Faster than instant. This is why we use rust. Optimize the shit out of it so its 100% instant

> And still - i want you to start so that this runs

> I want my mac and debian to be synced.

> alter youve made sure it actually works for the whole ce-net directories on both machines so that they are 100% in sync except ceignore files - add support for many different machines at once not ust two. should be trivial.

> You have access to debian. Fix the blob dht transport or whatever you said. Deploy so it actually works and syncs my directories using this system - mac to debian back and fourth

> Remote build failed

> commit and push and deploy everything after

> Is my debian properly synced now? No its not... My debian is not at all properly synced.

> its still not in sync. check the notes directory in mac and then debian and youll see. Dont do anything manually. this must work for everything by default. Now i see all of the uncoitted changes locally because it shows up in the editor on debian. commit and deploy and update everything so that github is up to date.

> And its still not synced properly to debian. are you kidding. No I told you the correct model before: we track diffs precisely in git repos and initilized once. places without git repos are handled differently with our own merge system. No git repo for stuff which shouldnt have it like temporary directories and root files: like would the AGENTS.md file be its own git repo lol. what were you thinking. its a lot faster now. do the rebuild. but if you can build on my debian desktop for mac

> last writeer wins? do we have a line by line diff and merge system? last writer wins sounds like something will be removed.

> Its so slow. why isnt it instant? the notes directory is still note synced. Like what. Update debian then. keep things in sync. Also aint no way im running that command. Like what the fuck. Make a proper system not this bullshit. one command = one active node. Another simple command for pairing. No gmail to send long complex commands anymore. but keep security. you have to verify each connection and scopes and auth.

## Tooling / branding
> rename from rdev - what is rdev? call it something else

> ce-dev is a horrible name for it. what is it really? its nor for development. and why would you want to seperate it out like this. ce-drive handles remote execution also. ce-drive is like a distributed personal operating system with remote execution and files and everything. very fast. very efficent and powerful. very secure. ce up and ce pair is good.

> yes but rename rdev to something else. Or is rdev our own tool? Create proper ce branded tooling for all of this - rename what we already have- redocument.

> Do all of it

> you should be able to ssh in and setup a ce node if you have remote access easily on any machine. useful tool. use it to ssh into my debian. and setup ce on it

> USE LIBp2p AND OUR MESH USE ce-net

## Binaries / distribution
> So ce-hub should store the binaries and stuff for download - distributed and hash check summed

> I got bad download. and is this secure? "take over completely from here from over the mesh"

## Testing on VMs
> Do this. Build this. Test it on vms on the relay

> automated e2e tests on vms

> using vms

> Write real e2e tests setting up ce nodes on fresh vms in the ce-iam repo which tests everything distributed, fault tolerance and secuirty and try take over.

## Auth (ce-iam)
> switch to the new ce-iam for auth. Do all of it right now.

> Yes go after everything. this is production systems were making. iterate on its api until perfection. make it feel like claude with its two factor auth and stuff. plan adding bankid, google login and other login services and distributed auth providers to the auth systems to build trust and tie nodes to real world identities.

> write phase 2, 3, 4, 5, 6. Verify security and browser behaviour. verify local node to browser connection and that ce-iam detects and sees that its the same node with correct behaviour and check that vault access for specific nodes work properly.

> Doccument exactly what ive said word for word. commit and push and deploy.
