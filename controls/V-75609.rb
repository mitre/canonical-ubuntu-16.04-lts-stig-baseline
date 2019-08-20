control "V-75609" do
  title "Library files must be group-owned by root."
  desc  "If the Ubuntu operating system were to allow any user to make changes
to software libraries, then those changes might be implemented without
undergoing the appropriate testing and approvals that are part of a robust
change management process.

    This requirement applies to Ubuntu operating systems with software
libraries that are accessible and configurable, as in the case of interpreted
languages. Software libraries also include privileged programs which execute
with escalated privileges. Only qualified and authorized individuals shall be
allowed to obtain access to information system components for purposes of
initiating changes, including upgrades and modifications.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000259-GPOS-00100"
  tag "gid": "V-75609"
  tag "rid": "SV-90289r2_rule"
  tag "stig_id": "UBTU-16-011020"
  tag "fix_id": "F-82237r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  desc "check", "Verify the system-wide shared library files contained in the
following directories are group-owned by \"root\".

Check that the system-wide shared library files are group-owned by \"root\"
with the following command:

# sudo find /lib /usr/lib /lib64 ! -group root | xargs ls -la

If any system wide shared library file is returned, this is a finding."
  desc "fix", "Configure the library files to be protected from unauthorized
access.

Run the following command, replacing \"[FILE]\" with any library file not
group-owned by root.

# sudo chgrp root [FILE]"

  if os.arch == "x86_64"
    library_files = command('find /lib /usr/lib /usr/lib32 /lib32 /lib64 ! \-group root').stdout.strip.split("\n").entries
  else
    library_files = command('find /lib /usr/lib /usr/lib32 /lib32 ! \-group root').stdout.strip.split("\n").entries
  end

  if library_files.count > 0
    library_files.each do |lib_file|
      describe file(lib_file) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Number of system-wide shared library files found that are NOT group-owned by root" do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end

