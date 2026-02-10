.. role:: since

=============================
Secret storage and encryption
=============================

.. contents::

The secret objects can either be ephemeral or persistent.
Ephemeral secrets are only kept in memory, never stored persistently on the disk.
See `Secrets <formatsecret.html>`__

:since:`Since 12.1.0` if a secret is defined as persistent, then it is stored **encrypted** on the disk.


Systemd Credentials Sealing
---------------------------

Out of the box, secrets are sealed using systemd credentials. This ties the
encrypted secret files to the specific host.

The `virt-secret-init-encryption` service automatically generates a random
32-byte key and encrypts it using `systemd-creds`, storing the result in
`/var/lib/libvirt/secrets/secrets-encryption-key`. The `virtsecretd` service
then automatically loads this key securely via the systemd `LoadCredentialEncrypted`
mechanism.

Disabling Systemd Credentials
-----------------------------

You can control encryption behavior by editing the `secret.conf` configuration
file located in ``@SYSCONFDIR@/libvirt/secret.conf`` or ``$XDG_CONFIG_HOME/libvirt/secret.conf``
depending on how the daemon was started (system mode or session mode respectively).

To **disable encryption entirely** (which effectively disables the use of any
systemd credentials for this purpose):

::

   encrypt_data = 0

Setting ``encrypt_data = 0`` takes precedence over any available systemd
credentials. If you have existing encrypted secrets, this setting will prevent
the secret driver from loading the encryption key, making those secrets
inaccessible. New or updated secrets will be stored in plain base64 format.

To **use a custom encryption key** instead of the systemd credential.
Defining a custom key path takes precedence over the systemd credential

::

   secrets_encryption_key = "/path/to/custom/key"

Configuring Encryption on Non-Systemd Hosts
-------------------------------------------

On hosts without systemd, or if you prefer to manage the key manually, you can
create a raw encryption key and configure libvirt to use it.

Generate a random 32-byte key:

::

   dd if=/dev/random of=/path/to/key/file bs=32 count=1

Update `secret.conf` to point to this key:

::

   secrets_encryption_key = "/path/to/key/file"

Manual Systemd Credential Creation
----------------------------------

If you want to use systemd credentials but need to customize the encryption parameters
(for example, to specify which TPM PCRs to bind to), you can generate the
credential file manually.

To create the default `/var/lib/libvirt/secrets/secrets-encryption-key` manually
using `systemd-creds` (adjusting arguments to `systemd-creds encrypt` as needed):

::

   dd if=/dev/random bs=32 count=1 | \
   systemd-creds encrypt --name=secrets-encryption-key - \
   /var/lib/libvirt/secrets/secrets-encryption-key

You can pass extra arguments to `systemd-creds encrypt <https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html?#encrypt%20input%7C-%20output%7C->`__,
such as ``--tpm2-device=...`` or ``--tpm2-pcrs=...``, to customize the sealing policy.

Upgrading Libvirt for secret encryption
---------------------------------------
:since:`Since 12.1.0`, secrets can be stored on the disk in an encrypted format,
rather than the default base64 encoding.

Any secret created before upgrading libvirt, remain stored in their original base64
format on the disk.
A pre-existing secret will only be encrypted if you explicitly update its value using
**virsh secret-set-value** after the upgrade, provided that encryption is enabled in
secret.conf configuration file.

It is important to note that encrypted secrets are not backwards compatible. In
case of a downgrade to an older version of libvirt, the encrypted secrets will
not be loaded from the disk. Therefore, before reverting to an older version
libvirt, make sure that all the secrets have been reverted to the standard
base64 format, to avoid service disruptions.
