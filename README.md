Minor changes to 86Box network options to make it easier for me with MacOS.  
Implements support for Apple vmnet to provide vmnet NAT, vmnet HOST, vmnet BRIDGE options.  
Leverages a priviledge helper needed to access vmnet, simply compile and install once using the supplied scripts.

Patch file
==========

`86Box-vmnet.patch` contains the vmnet integration and helper package as a
single patch against a clean checkout of the upstream 86Box repository.

Tested against 86Box `v6.0-3185-gfa1c79bb8` (commit
`fa1c79bb8b18f4815deb530c86500453cd0e4ff0`). The patch may require manual
adjustments when applied to a different 86Box revision.

Apply it from the root of a clean 86Box checkout with:

```sh
patch -p1 < /path/to/86Box-vmnet.patch
```

Then configure and build 86Box normally. Build and install the privileged
vmnet helper separately from the patched checkout:

```sh
make -C vmnet
cd vmnet
sudo ./scripts/install-launchd.sh
```

<pre>
Screenshots
===========
Config.png  - 86Box network configuration settings 
Booting.png - Just for show
Booted.png  - Ping working, arp and ifconfig
</pre>
