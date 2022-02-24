
Procedure BeforeWrite(Cancel)
	
	If Not StrEndsWith(PublicEndpoint, "/") Then   
		PublicEndpoint = PublicEndpoint + "/";
	EndIf;   
	
	If Not StrEndsWith(InitialFolder, "/") Then   
		InitialFolder = InitialFolder + "/";
	EndIf;  
	
EndProcedure
