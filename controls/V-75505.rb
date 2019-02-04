control "V-75505" do
  title "Ubuntu operating systems booted with a BIOS must require
authentication upon booting into single-user and maintenance modes."
  desc  "To mitigate the risk of unauthorized access to sensitive information
by entities that have been issued certificates by DoD-approved PKIs, all DoD
systems (e.g., web servers and web portals) must be properly configured to
incorporate access control methods that do not rely solely on the possession of
a certificate for access. Successful authentication must not automatically give
an entity access to an asset or security boundary. Authorization procedures and
controls must be implemented to ensure each authenticated entity also has a
validated and current authorization. Authorization is the process of
determining whether an entity, once authenticated, is permitted to access a
specific asset. Information systems use access control policies and enforcement
mechanisms to implement this requirement.

    Access control policies include: identity-based policies, role-based
policies, and attribute-based policies. Access enforcement mechanisms include:
access control lists, access control matrices, and cryptography. These policies
and mechanisms must be employed by the application to control access between
users (or processes acting on behalf of users) and objects (e.g., devices,
files, records, processes, programs, and domains) in the information system.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-75505"
  tag "rid": "SV-90185r2_rule"
  tag "stig_id": "UBTU-16-010380"
  tag "fix_id": "F-82133r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify that an encrypted root password is set. This is only
applicable on systems that use a basic Input/Output System BIOS.

Run the following command to verify the encrypted password is set:

# grep –i password /boot/grub/grub.cfg

password_pbkdf2 root grub.pbkdf2.sha512.10000.MFU48934NJA87HF8NSD34493GDHF84NG

If the root password entry does not begin with “password_pbkdf2”, this is a
finding."
  desc "fix", "Configure the system to require a password for authentication
upon booting into single-user and maintenance modes.

Generate an encrypted (grub) password for root with the following command:

# grub-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is
grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using the hash from the output, modify the \"/etc/grub.d/10_linux\" file with
the following command to add a boot password for the root entry:

# cat << EOF > set superusers=\"root\" password_pbkdf2 root
grub.pbkdf2.sha512.VeryLongString > EOF

Generate an updated \"grub.conf\" file with the new password by using the
following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/grub2/grub.cfg"
end

