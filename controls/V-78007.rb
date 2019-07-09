control "V-78007" do
  title "The system must update the DoD-approved virus scan program every seven
days or more frequently."
  desc  "Virus scanning software can be used to protect a system from
penetration from computer viruses and to limit their spread through
intermediate systems.

    The virus scanning software should be configured to check for software and
virus definition updates with a frequency no longer than seven days. If a
manual process is required to update the virus scan software or definitions, it
must be documented with the Information System Security Officer (ISSO).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-78007"
  tag "rid": "SV-92703r1_rule"
  tag "stig_id": "UBTU-16-030910"
  tag "fix_id": "F-84717r1_fix"
  tag "cci": ["CCI-001668"]
  tag "nist": ["SI-3 a", "Rev_4"]
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
  desc "check", "Verify the system is using a DoD-approved virus scan program
and the virus definition file is less than seven days old.

Check for the presence of \"McAfee VirusScan Enterprise for Linux\" with the
following command:

# systemctl status nails

nails - service for McAfee VirusScan Enterprise for Linux

> Loaded: loaded
/opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>;
enabled)

> Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the \"nails\" service is not active, check for the presence of \"clamav\" on
the system with the following command:

# systemctl status clamav-daemon.socket

systemctl status clamav-daemon.socket

clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon

Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)

Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If \"McAfee VirusScan Enterprise for Linux\" is active on the system, check the
dates of the virus definition files with the following command:

# ls -al /opt/NAI/LinuxShield/engine/dat/*.dat

-rwxr-xr-x 1 root root 243217 Mar 5 2017 avvclean.dat
-rwxr-xr-x 1 root root 16995 Mar 5 2017 avvnames.dat
-rwxr-xr-x 1 root root 4713245 Mar 5 2017 avvscan.dat

If the virus definition files have dates older than seven days from the current
date, this is a finding.

If \"clamav\" is active on the system, check the dates of the virus database
with the following commands:

# grep -I databasedirectory /etc/clamav.conf

DatabaseDirectory /var/lib/clamav

# ls -al /var/lib/clamav/*.cvd

-rwxr-xr-x 1 root root 149156 Mar 5 2011 daily.cvd

If the database file has a date older than seven days from the current date,
this is a finding.
"
  desc "fix", "Update the approved DoD virus scan software and virus definition
files."

  is_antivirus_active = false
  seven_days = 604800 # (7 days * 24 hours * 60 minutes * 60 seconds)
  
  # McAfee VirusScan Enterprise for Linux
  def_files = command("find /opt/NAI/LinuxShield/engine/dat -type f -name *.dat").stdout.split("\n")
  if ( service('nails').installed? && service('nails').enabled? && service('nails').running? )
    if !def_files.nil? and !def_files.empty?
      def_files.each do |deffile|
        describe file(deffile) do
          its('mtime') { should >= Time.now.to_i - seven_days }
        end
      end
    else
      describe "No McAfee VirusScan Enterprise for Linux definition files have been found" do
        subject { def_files.nil? or def_files.empty? }
        it { should eq false }
      end
    end
    is_antivirus_active = true
  end
  
  # ClamAV
  def_files = command("find /var/lib/clamav -type f -name *.cvd").stdout.split("\n")
  if ( service('clamav-daemon.service').installed? && service('clamav-daemon.service').enabled? && service('clamav-daemon.service').running? )
    if !def_files.nil? and !def_files.empty?
      def_files.each do |deffile|
        describe file(deffile) do
          its('mtime') { should >= Time.now.to_i - seven_days }
        end
      end
    else
      describe "No ClamAV definition files have been found" do
        subject { def_files.nil? or def_files.empty? }
        it { should eq false }
      end
    end
    is_antivirus_active = true
  end

  if !is_antivirus_active
    describe "No DoD-approved virus scan program is found to be active on the system" do
      subject { is_antivirus_active }
      it { should be true }
    end
  end
end

