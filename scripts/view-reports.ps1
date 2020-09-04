#This PowerShell script leverages Qualys API to retrieve list of latest scanned reports

#Step (a) -> Define variables
$username = "<<username>>"  #replace with your valid username
$password = "<<password>>"  #replace with your password value
$headertype = @{"X-Requested-With"="powershell"}  
$baseurl = "https://qualysapi.qualys.com/api/2.0/fo"  
$body = "action=login&username=$username&password=$password"  


#Step (b) -> Setup a session with Qualys by defining the headertype followed by the web path, method type, action to be performed and session object
$login=Invoke-RestMethod -Headers $headertype -Uri "$baseurl/session/" -Method Post -Body $body -SessionVariable sess  

if($login.Value -ne $null) #check if sessions is being established
{
echo "Issue in connecting to Qualys server"
exit 0
}

#Step (c) -> Get the latest list of scanned reports
$rpts = (Invoke-RestMethod -Headers $headertype -Uri "$baseurl/report?action=list" -WebSession $sess). SelectNodes("//REPORT") 
$objs = @ ()  

#Step (d) -> Organize the results in an array object with required column names
foreach ($record in $rpts) 
{  
  $obj = New-Object PSObject  
  
  if($record.LAUNCH_DATETIME -like "2020*") #check for reports scanned in year 2020
  {
  Add-Member -InputObject $obj -MemberType NoteProperty -Name ID -Value $record.ID
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Title -Value $record.TITLE."#cdata-section"  
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Timestamp -Value $record.LAUNCH_DATETIME  
  $objs += $obj  
  }
}  


#Step (e) -> Display the latest scan report information
$objs | Sort -Descending -Property Timestamp | Format-Table 
 

#Step (f) -> Logout from the session
$logout=Invoke-RestMethod -Headers $headertype -Uri "$baseurl/session/" -Method Post -Body "action=logout" -WebSession $sess  

if($logout.Value -eq $null)  #check if sessions is logged out 
{
echo "Logging out from Qualys server..."
}

#Script ended
