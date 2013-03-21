#include <stdio.h>
#define _WIN32_DCOM

#include "wbemCli.h"
#include "wbemprov.h"
#include "wbemtran.h"
#include <objbase.h>

// ole32,oleaut32,wbemuuid
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

int main()
{
  // Initialize COM
  CoInitializeEx(0, COINIT_MULTITHREADED);
	
//******************************************************************************
printf( "<html>\r\n"
        "<center><BIG>显示杀毒软件信息</BIG></center>"
        "[Index]<br/><br/>"
        "<a href=\"#1\">Antivirus</a><br/><br/><hr/>");

//------------------------------------------------------------------------------
  
  IEnumWbemClassObject *pEnumerator = NULL;
// Set general COM security levels 
  if(CoInitializeSecurity( NULL,-1,NULL,NULL,
    		RPC_C_AUTHN_LEVEL_DEFAULT,//RPC_C_AUTHN_LEVEL_PKT,
    		RPC_C_IMP_LEVEL_IMPERSONATE,//RPC_C_IMP_LEVEL_DEFAULT,//RPC_C_IMP_LEVEL_IMPERSONATE, 
    		NULL,EOAC_NONE,NULL
    ) != S_OK) printf("error - CoInitializeSecurity\n");		

// Connect to WMI through the IWbemLocator::ConnectServer method
// Obtain the initial locator to WMI
   IWbemLocator *mpLoc = NULL;
   IWbemServices *mpSvc = NULL;
   
   if(FAILED(CoCreateInstance(CLSID_WbemLocator,NULL,CLSCTX_INPROC_SERVER,
           IID_IWbemLocator, (LPVOID *) &mpLoc))
   ) printf("error - CoCreateInstance\n");  
  
// Connect to the root\SecurityCenter namespace with
// the current user and obtain pointer pSvc
// to make IWbemServices calls.  
   if(FAILED(mpLoc->ConnectServer(
            BSTR(L"ROOT\\SecurityCenter"),   //Object path of WMI namespace
            NULL,                   //User name. NULL = current user
            NULL,                   //User password. NULL = current
            0,                      //Locale. NULL indicates current
            0,                      //Security flags
            0,                      //Authority(NTLM domain)
            0,                      //Context object
            &mpSvc))                //Pointer to IWbemServices proxy
   )printf("error - ConnectServer SecurityCenter\n");

   // Set the IWbemServices proxy so that impersonation
   // of the user (client) occurs.
   if(FAILED(CoSetProxyBlanket(
       mpSvc,                         // the proxy to set
       RPC_C_AUTHN_WINNT,            // authentication service
       RPC_C_AUTHZ_NONE,             // authorization service
       NULL,                         // Server principal name
       RPC_C_AUTHN_LEVEL_CALL,       // authentication level
       RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
       NULL,                         // client identity 
       EOAC_NONE                     // proxy capabilities     
    )))printf("error - CoSetProxyBlanket SecurityCenter\n");  

printf("\r\n\t<br/><br/><a name=\"1\"></a><big>[Antivirus:]</big>\r\n");
    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    // For example, query for all the running processes

    if (FAILED(mpSvc->ExecQuery(
        BSTR(L"WQL"),
        BSTR(L"SELECT * FROM AntiVirusProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator)))printf("error - ExecQuery AntiVirusProduct\n");
    else
    { 
        printf("\t<table border=\"1px\">\r\n");        
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
        unsigned short nb=0;
        printf("\t\t<tr bgcolor=\"gray\">\r\n\t\t\t<td><font color=\"FFFFFF\">Name</font></td><td><font color=\"FFFFFF\">Description</font></td>\r\n\t\t</tr>\r\n");
        
        while (pEnumerator)
        {
            pEnumerator->Next(WBEM_INFINITE, 1,&pclsObj, &uReturn);

            if(0 == uReturn)break;

            VARIANT vtProp;
            
            //displayName
            pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
            printf("\t\t<tr%s>\r\n\t\t\t<td>%S</td><td>",nb++%2==1?" bgcolor=\"silver\"":"",vtProp.bstrVal);

            //companyName
            pclsObj->Get(L"companyName", 0, &vtProp, 0, 0);
            printf("CompanyName: %S<br/>\r\n",vtProp.bstrVal);                  
            
            //versionNumber
            pclsObj->Get(L"versionNumber", 0, &vtProp, 0, 0);
            printf("VersionNumber: %S</td>\r\n\t\t</tr>\r\n",vtProp.bstrVal);
                               
            VariantClear(&vtProp);
            pclsObj->Release();
        }
        pEnumerator->Release(); 
        printf("\t</table>\r\n");        
    }     
  
printf("\r\n</html>\r\n");  
        
  mpSvc->Release();    
  mpLoc->Release();   
  CoUninitialize();
 // system("PAUSE");	
  return 0;
}

