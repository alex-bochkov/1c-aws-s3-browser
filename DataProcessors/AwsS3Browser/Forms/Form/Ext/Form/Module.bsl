#Region HMAC_SHA256

Function Hash(BinaryData, Type)
	
	HashingObj = New DataHashing(Type);
	HashingObj.Append(BinaryData);
	
	Return HashingObj.HashSum;
		
EndFunction   

Function HashFromFile(FileName, Type)
	
	HashingObj = New DataHashing(Type);
	HashingObj.AppendFile(FileName);
	
	Return HashingObj.HashSum;
		
EndFunction  

Function HMAC(Val KeyValue, Val Data, Type, BlockSize)
	
	If KeyValue.Size() > BlockSize Then
		KeyValue = Hash(KeyValue, Type);
	EndIf;
	
	If KeyValue.Size() < BlockSize Then
		KeyValue = GetHexStringFromBinaryData(KeyValue);
		KeyValue = Left(KeyValue + RepeatString("00", BlockSize), BlockSize * 2);
	EndIf;
	
	KeyValue = GetBinaryDataBufferFromBinaryData(GetBinaryDataFromHexString(KeyValue));
	
	ipad = GetBinaryDataBufferFromHexString(RepeatString("36", BlockSize));
	opad = GetBinaryDataBufferFromHexString(RepeatString("5c", BlockSize));
	
	ipad.WriteBitwiseXor(0, KeyValue);
	ikeypad = GetBinaryDataFromBinaryDataBuffer(ipad);
	
	opad.WriteBitwiseXor(0, KeyValue);
	okeypad = GetBinaryDataFromBinaryDataBuffer(opad);
	
	Return Hash(CombineBinaryData(okeypad, Hash(CombineBinaryData(ikeypad, Data), Type)), Type);
	
EndFunction

Function CombineBinaryData(BinaryData1, BinaryData2)
	
	BinaryArray = New Array;
	BinaryArray.Add(BinaryData1);
	BinaryArray.Add(BinaryData2);
	
	Return ConcatBinaryData(BinaryArray);
	
EndFunction

Function RepeatString(String, Count)
	
	Parts = New Array(Count);
	For i = 1 To Count Do
		Parts.Add(String);
	EndDo;
	
	Return StrConcat(Parts, "");
	
EndFunction    

Function HMACSHA256(Val Key, Val Data)
	
	Return HMAC(Key, Data, HashFunction.SHA256, 64);
	
EndFunction
              
Function GetSignatureKey(key, dateStamp, regionName, serviceName) 
	
	kSecret 	= GetBinaryDataFromString("AWS4" + key);	     
	kDate 		= HMACSHA256(kSecret, 	GetBinaryDataFromString(dateStamp));
	kRegion 	= HMACSHA256(kDate, 	GetBinaryDataFromString(regionName));
	kService 	= HMACSHA256(kRegion, 	GetBinaryDataFromString(serviceName));
	kSigning 	= HMACSHA256(kService, 	GetBinaryDataFromString("aws4_request"));

    Return kSigning; 
	
EndFunction   

#EndRegion

#Region AWS_Request
&AtServer 
Procedure ParseXmlResponse(ResponseText)   
	
	Object.BucketObjects.Clear();   
	
	XMLReader = New XMLReader;
	XMLReader.SetString(ResponseText); 
	
	Obj = XDTOFactory.ReadXML(XMLReader);   
	
	Object.m_IsTruncated = Boolean(Obj.IsTruncated);    
	If Object.m_IsTruncated Then
		Object.m_NextContinuationToken = Obj.NextContinuationToken;	  
	Else 
		Object.m_NextContinuationToken = "";
	EndIf;           
	If TypeOf(Obj.Prefix) = Type("String") Then 
		Object.m_Prefix = Obj.Prefix;        
	Else 
		Object.m_Prefix = ""
	EndIf;
	
	If Not Obj.Properties().Get("CommonPrefixes") = Undefined Then   
		
		If TypeOf(Obj.CommonPrefixes) = Type("XDTODataObject") Then   
			Array = New Array;
			Array.Add(Obj.CommonPrefixes);
		Else 
			Array = Obj.CommonPrefixes;
		EndIf;	  
		
		For Each CommonPrefix in Array Do    
			NewRow = Object.BucketObjects.Add();  
			NewRow.isFolder 		= True;
			NewRow.Key 				= CommonPrefix.Prefix;
			NewRow.ObjectShortName 	= Mid(CommonPrefix.Prefix, StrLen(Object.m_Prefix) + 1);
		EndDo;  
	EndIf;
	
	If Not Obj.Properties().Get("Contents") = Undefined Then  
		
		If TypeOf(Obj.Contents) = Type("XDTODataObject") Then   
			Array = New Array;
			Array.Add(Obj.Contents);
		Else 
			Array = Obj.Contents;
		EndIf;	  
		
		For Each Content in Array Do     
			NewRow = Object.BucketObjects.Add();  
			NewRow.isFolder 		= False;
			NewRow.Key 				= Content.Key;
			NewRow.LastModified 	= XMLValue(Type("Date"), Content.LastModified);
			NewRow.ETag 			= Content.ETag;
			NewRow.Size 			= Content.Size;
			NewRow.StorageClass 	= Content.StorageClass;
			NewRow.ObjectShortName 	= Mid(Content.Key, StrLen(Object.m_Prefix) + 1);  
		EndDo;       
			
		
	EndIf;          
	
	Object.BucketObjects.Sort("isFolder DESC, Key");
	
EndProcedure

&AtServer
Procedure ListObjectsAtServer(Prefix)  
	
	ExecuteCommand("ListFiles", Prefix);
	
EndProcedure	
	
&AtServer
Procedure ExecuteCommand(Command, CurrentPrefix, LocalFilePath = Undefined, FileContentType = Undefined)  
	
	HostS3 = "s3.amazonaws.com";          
	AbsolutePath = "/" + Object.BucketName + "/";
	
	contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; //empty string       
	contentType = ""; //"text/plain";           
	verb 		= "GET";      
	
	Prefix 		  = StrReplace(EncodeString(CurrentPrefix, StringEncodingMethod.URLEncoding), "%2F", "/");  
	PrefixEncoded = EncodeString(CurrentPrefix, StringEncodingMethod.URLEncoding);  
	
	queryParams = "delimiter=%2F&list-type=2&max-keys=" + Object.MaxKeysPerRequest + "&prefix=" + PrefixEncoded;   
	
	uri = AbsolutePath  + "?delimiter=/&list-type=2&max-keys=" + Object.MaxKeysPerRequest + "&prefix=" + Prefix;       
	
	If Command = "UploadFile" Then   
		
		verb 		= "PUT";    
		queryParams = "";    
		uri			= AbsolutePath + CurrentPrefix;    
		AbsolutePath = uri;   
		
		If Not FileContentType = Undefined Then
			contentType = FileContentType; 
		EndIf;    
		
		If Not LocalFilePath = Undefined Then
			contentHash = Lower(GetHexStringFromBinaryData(HashFromFile(LocalFilePath, HashFunction.SHA256)));	  
		EndIf;   
		
	ElsIf Command = "DeleteFile" Then 
		
		verb 			= "DELETE";    
		queryParams 	= "";    
		uri				= AbsolutePath + CurrentPrefix;    
		AbsolutePath 	= uri; 
		
	EndIf;
	
	date 	  = Format(CurrentUniversalDate(), "DF=yyyyMMddTHHmmssZ");
	dateStamp = Format(CurrentUniversalDate(), "DF=yyyyMMdd");   
	
	scope = dateStamp + "/" + Object.Region + "/" + Object.Service + "/aws4_request";    
	
	NewLine = Chars.LF;     
	
	canonicalRequestPlain = verb + NewLine +
		AbsolutePath + NewLine +
		queryParams + NewLine + 
		"content-type:" + contentType + NewLine +   
		"host:" + HostS3 + NewLine  +
		"x-amz-content-sha256:" + contentHash + NewLine  +
		"x-amz-date:" + date + NewLine + 
		NewLine +
		"content-type;host;x-amz-content-sha256;x-amz-date" + NewLine +
		"" + contentHash;
		
	canonicalRequestByte = Hash(canonicalRequestPlain, HashFunction.SHA256);    
	
	canonicalRequestHash = Lower(GetHexStringFromBinaryData(canonicalRequestByte)); 
	
	stringToSign = "AWS4-HMAC-SHA256" + NewLine + date + NewLine + scope + NewLine + canonicalRequestHash;	
	
	sign = GetSignatureKey(Object.SecretKey, dateStamp, Object.Region, Object.Service);
	
	signatureByte = HMACSHA256(sign, GetBinaryDataFromString(stringToSign));   
	
	signatureHash = Lower(GetHexStringFromBinaryData(signatureByte));
	
	Authorization = "AWS4-HMAC-SHA256 Credential=" + Object.AccessKey + "/" + scope 
		+ ",SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,Signature=" + signatureHash;
	
	headers = New Map();
	headers.Insert("Host", 					HostS3);
	headers.Insert("Content-Type", 			contentType);
	headers.Insert("x-amz-content-sha256", 	contentHash);
	headers.Insert("x-amz-date", 			date);
	headers.Insert("Authorization", 		Authorization);     
	
	Query = New HTTPRequest( uri, headers);     
	If Not LocalFilePath = Undefined Then
		Query.SetBodyFileName(LocalFilePath);
	EndIf;
	
	Connection = New HTTPConnection(HostS3, 443,,,,, New OpenSSLSecureConnection);  
	
	Result = Connection.CallHTTPMethod(verb, Query);    

	Object.RequestText = canonicalRequestPlain;
	
	Object.ResponseText = Result.GetBodyAsString();  
	
	NewLog = Object.RequestLogs.Add(); 
	NewLog.Date 		= CurrentDate();	
	NewLog.StatusCode 	= Result.StatusCode;
	NewLog.Request 		= Object.RequestText;
	NewLog.Response 	= Object.ResponseText;
	
	If Result.StatusCode = 200 
		OR Result.StatusCode = 204 Then 
		
		If ValueIsFilled(Object.ResponseText) Then
			ParseXmlResponse(Object.ResponseText);        
		EndIf;
		
	Else       
		
		Message("The request has failed with the status code = " + Result.StatusCode);  
		
		Items.GroupPages.CurrentPage = items.GroupRequestLog;
		
	EndIf;
	
	
EndProcedure

#EndRegion



&AtServer
Procedure OnCreateAtServer(Cancel, StandardProcessing)     
	
	
	
EndProcedure  

&AtClient
Procedure BucketOnChange(Item)

	 BucketOnChangeAtServer();

EndProcedure

&AtServer
Procedure BucketOnChangeAtServer()   
	
	Object.AccessKey 			= Object.Bucket.AccessKeyId;	
	Object.SecretKey 			= Object.Bucket.SecretAccessKey;      
	Object.BucketName 			= Object.Bucket.BucketName;
    Object.Region 				= Object.Bucket.Region;	      
	Object.Service 				= "s3";    
	Object.MaxKeysPerRequest 	= Object.Bucket.MaxKeysPerRequest;  
	Object.PublicEndpoint 		= Object.Bucket.PublicEndpoint;
	Object.m_Prefix 			= Object.Bucket.InitialFolder;
	
	Items.BucketObjectsContextMenuOpenInBrowser.Visible = ValueIsFilled(Object.PublicEndpoint);  
	
	ListObjectsAtServer(Object.m_Prefix);

EndProcedure

&AtClient
Procedure ListObjects(Command)   
	
	ListObjectsAtServer(Object.m_Prefix); 
	
EndProcedure

&AtClient
Procedure BucketObjectsSelection(Item, SelectedRow, Field, StandardProcessing)  
	
	If Not Item.CurrentData = Undefined Then		
		
		If Item.CurrentData.isFolder Then  
		
			SelectedFolder = Item.CurrentData.Key;
			
			ListObjectsAtServer(SelectedFolder);
			
		EndIf;
		
	EndIf;
	
EndProcedure

&AtClient
Procedure ReturnOneLevelUp(Command)        
	
	CurrentFolder = Object.m_Prefix;    
	
	CurrentFolder = Left(CurrentFolder, StrFind(CurrentFolder, "/", SearchDirection.FromEnd,, 2));	   
	
	ListObjectsAtServer(CurrentFolder);
	
EndProcedure

&AtClient
Procedure CreateNewFolder(Command)    
	
	ToolTip = "Enter a name for the new folder";
	Notify = New NotifyDescription("CreateNewFolderAfterInputString", ThisObject);
	ShowInputString(Notify, "", ToolTip, 0, False);

EndProcedure       


&AtClient
Procedure CreateNewFolderAfterInputString(Sring, Parameters) Export   
	
	If Sring <> Undefined Then
		
        CreateNewFolderAtServer(Sring);

	EndIf;  
	
EndProcedure    

&AtServer
Procedure CreateNewFolderAtServer(ChosenFolderName)       
	
	Prefix = StrReplace(EncodeString(Object.m_Prefix + ChosenFolderName + "/", StringEncodingMethod.URLEncoding), "%2F", "/");	

	ExecuteCommand("UploadFile", Prefix);  
	
	ListObjectsAtServer(Object.m_Prefix); 
	
EndProcedure  

&AtClient
Procedure UploadNewFile(Command)

	Notification = New NotifyDescription("UploadFileHereCompletion", ThisObject);

	Dialog = New FileDialog(FileDialogMode.Open);          
	
	BeginPutFile(Notification, , Dialog, True, ThisObject.UUID);
		
EndProcedure   
 
&AtClient
Procedure UploadFileHereCompletion(Result, Address, ChosenFileName, ExtraParameters) Экспорт

	If Result Then
		UploadFileHereAtServer(Address, ChosenFileName); 
	Else
		Message("The file was not selected!");
	EndIf;

EndProcedure  

&AtServer
Procedure UploadFileHereAtServer(Address, ChosenFileName)     
	
	Data = GetFromTempStorage(Address);
	TempFileName = GetTempFileName();
	Data.Write(TempFileName);    
	
	ShortFileName = Right(ChosenFileName, StrLen(ChosenFileName) - StrFind(ChosenFileName, "\", SearchDirection.FromEnd));
	
	Prefix = StrReplace(EncodeString(Object.m_Prefix + ShortFileName, StringEncodingMethod.URLEncoding), "%2F", "/");	
	
	FileContentType = "image/png";
	If StrEndsWith(ShortFileName, ".jpg") Then   
		FileContentType = "image/jpeg";
	EndIf;
	
	ExecuteCommand("UploadFile", Prefix, TempFileName, FileContentType);  
	
	ListObjectsAtServer(Object.m_Prefix); 
	
	Try
		DeleteFiles(TempFileName);
	Except
	EndTry;
	
EndProcedure

&AtClient
Procedure OpenInBrowser(Command)   
	
	If Not Items.BucketObjects.CurrentData = Undefined Then    
		
		Url = Object.PublicEndpoint + Items.BucketObjects.CurrentData.Key;	
		
		RunAppAsync(Url,, False);	
		
	EndIf;
	
EndProcedure

&AtServer
Procedure DeleteObjectAtServer(ObjectShortName)        

	Prefix = StrReplace(EncodeString(Object.m_Prefix + ObjectShortName, StringEncodingMethod.URLEncoding), "%2F", "/");	
	
	ExecuteCommand("DeleteFile", Prefix);  
	
	ListObjectsAtServer(Object.m_Prefix); 
	
EndProcedure

&AtClient
Procedure DeleteObject(Command)      
	
	If Not Items.BucketObjects.CurrentData = Undefined Then
	
	    Notification = New NotifyDescription("DeleteObjectConfirmation", ThisObject);	
	 
	    ShowQueryBox(Notification,
	        "Do you want to delete [" + Items.BucketObjects.CurrentData.ObjectShortName + "] object?",
	        QuestionDialogMode.YesNoCancel,
	        60, // timeout in seconds
	        DialogReturnCode.Cancel,     
			"Please confirm deletion" 
	    );     
		
	EndIf;
	
EndProcedure       

&AtClient
Procedure DeleteObjectConfirmation(Rez, Paramaters) Export  
	
	If Rez = DialogReturnCode.Yes Then     
			
		DeleteObjectAtServer(Items.BucketObjects.CurrentData.ObjectShortName);
	
    EndIf;	
	
EndProcedure
 