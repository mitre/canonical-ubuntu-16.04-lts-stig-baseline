control "V-75551" do
  title "User accounts with temporary passwords, must require an immediate
change to a permanent password after login."
  desc  "Without providing this capability, an account may be created without a
password. Non-repudiation cannot be guaranteed once an account is created if a
user is not forced to change the temporary password upon initial logon.

    Temporary passwords are typically used to allow access when new accounts
are created or passwords are changed. It is common practice for administrators
to create temporary passwords for user accounts which allow the users to log
on, yet force them to change the password once they have successfully
authenticated.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000380-GPOS-00165"
  tag "gid": "V-75551"
  tag "rid": "SV-90231r1_rule"
  tag "stig_id": "UBTU-16-010680"
  tag "fix_id": "F-82179r1_fix"
  tag "cci": ["CCI-002041"]
  tag "nist": ["IA-5 (1) (f)", "Rev_4"]
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
  tag "check": "Verify a policy exists that ensures when a user account is
created, it is created using a method that forces a user to change their
password upon their next login.

If a policy does not exist, this is a finding."
  tag "fix": "Create a policy that ensures when a user is created, it is
created using a method that forces a user to change their password upon their
next login.

Below are two examples of how to create a user account that requires the user
to change their password upon their next login.

# chage -d 0 [UserName]

or

# passwd -e [UserName]"
end

