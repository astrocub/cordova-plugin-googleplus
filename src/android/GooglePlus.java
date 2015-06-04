package nl.xservices.plugins;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.auth.UserRecoverableAuthException;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.plus.Plus;
import com.google.android.gms.plus.model.people.Person;
import org.apache.cordova.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

public class GooglePlus extends CordovaPlugin implements ConnectionCallbacks, OnConnectionFailedListener {

  public static final String ACTION_IS_AVAILABLE = "isAvailable";
  public static final String ACTION_LOGIN = "login";
  public static final String ACTION_TRY_SILENT_LOGIN = "trySilentLogin";
  public static final String ACTION_LOGOUT = "logout";
  public static final String ACTION_DISCONNECT = "disconnect";
  public static final String ARGUMENT_ANDROID_KEY = "androidApiKey";
  public static final String ARGUMENT_WEB_KEY = "webApiKey";
  public static final String ARGUMENT_SERVER_CLIENT_ID = "serverClientId";
  public static final String ARGUMENT_SERVER_AUTH_URL = "authApiHost";

  // Wraps our service connection to Google Play services and provides access to the users sign in state and Google APIs
  private GoogleApiClient mGoogleApiClient;
  private String apiKey, webKey, serverClientId, serverAuthUrl;
  private CallbackContext savedCallbackContext;
  private boolean trySilentLogin;
  private boolean loggingOut;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    mGoogleApiClient = buildGoogleApiClient();
  }

  @Override
  public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
    this.savedCallbackContext = callbackContext;

    if (args.optJSONObject(0) != null){
      JSONObject obj = args.getJSONObject(0);
      System.out.println(obj);
      this.webKey = obj.optString(ARGUMENT_WEB_KEY, null);
      this.apiKey = obj.optString(ARGUMENT_ANDROID_KEY, null);
      this.serverClientId = obj.optString(ARGUMENT_SERVER_CLIENT_ID, null);
      this.serverAuthUrl = obj.optString(ARGUMENT_SERVER_AUTH_URL, null);
    }

    if (ACTION_IS_AVAILABLE.equals(action)) {
      final boolean avail = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this.cordova.getActivity().getApplicationContext()) == 0;
      savedCallbackContext.success("" + avail);

    } else if (ACTION_LOGIN.equals(action)) {
      this.trySilentLogin = false;
      mGoogleApiClient.reconnect();

    } else if (ACTION_TRY_SILENT_LOGIN.equals(action)) {
      this.trySilentLogin = true;
      mGoogleApiClient.reconnect();

    } else if (ACTION_LOGOUT.equals(action)) {
      try {
        Plus.AccountApi.clearDefaultAccount(mGoogleApiClient);
        mGoogleApiClient.disconnect();
        // needed in onActivityResult when the connect method below comes back
        loggingOut = true;
        mGoogleApiClient = buildGoogleApiClient();
        mGoogleApiClient.connect();
      } catch (IllegalStateException ignore) {
      }
      savedCallbackContext.success("logged out");

    } else if (ACTION_DISCONNECT.equals(action)) {
      disconnect();
    } else {
      return false;
    }
    return true;
  }

  private void disconnect() {
    try {
      Plus.AccountApi.revokeAccessAndDisconnect(mGoogleApiClient)
          .setResultCallback(new ResultCallback<Status>() {
            @Override
            public void onResult(Status status) {
              // mGoogleApiClient is now disconnected and access has been revoked.
              // Don't care if it was disconnected already (status != success).
              mGoogleApiClient = buildGoogleApiClient();
              savedCallbackContext.success("disconnected");
            }
          });
    } catch (IllegalStateException e) {
      savedCallbackContext.success("disconnected");
    }
  }
    private GoogleApiClient buildGoogleApiClient() {
		return new GoogleApiClient.Builder(webView.getContext())
        .addConnectionCallbacks(this)
        .addOnConnectionFailedListener(this)
        .addApi(Plus.API, Plus.PlusOptions.builder().build())
        .addScope(Plus.SCOPE_PLUS_LOGIN)
		.addScope(Plus.SCOPE_PROFILE)
		.addScope(new Scope("https://www.googleapis.com/auth/userinfo.email"))
        .addScope(new Scope("https://www.googleapis.com/auth/calendar"))
        .addScope(new Scope("https://apps-apis.google.com/a/feeds/calendar/resource/"))
        .addScope(new Scope("https://www.googleapis.com/auth/admin.directory.user.readonly"))
        .addScope(new Scope("https://www.googleapis.com/auth/admin.directory.user"))
		//.requestServerAuthCode(SERVER_CLIENT_ID, this)
        .build();
  }
  
    /**
   * onConnected is called when our Activity successfully connects to Google
   * Play services.  onConnected indicates that an account was selected on the
   * device, that the selected account has granted any requested permissions to
   * our app and that we were able to establish a service connection to Google
   * Play services.
   */
  @Override
  public void onConnected(Bundle connectionHint) {
    final String email = Plus.AccountApi.getAccountName(mGoogleApiClient);
    final Person user = Plus.PeopleApi.getCurrentPerson(mGoogleApiClient);

    final JSONObject result = new JSONObject();
    try {
      result.put("email", email);
      // in case there was no internet connection, this may be null
      if (user != null) {
        result.put("userId", user.getId());
        result.put("displayName", user.getDisplayName());
        if (user.getImage() != null) {
          result.put("imageUrl", user.getImage().getUrl());
        }
        if (user.getName() != null) {
          result.put("givenName", user.getName().getGivenName());
          result.put("middleName", user.getName().getMiddleName());
          result.put("familyName", user.getName().getFamilyName());
        }
      }
      resolveToken(email, result);
    } catch (JSONException e) {
      savedCallbackContext.error("result parsing trouble, error: " + e.getMessage());
    }
  }

    @Override
  public void onConnectionSuspended(int constantInClass_ConnectionCallbacks) {
    this.savedCallbackContext.error("connection trouble, code: " + constantInClass_ConnectionCallbacks);
  }

  /**
   * onConnectionFailed is called when our Activity could not connect to Google Play services.
   * onConnectionFailed indicates that the user needs to select an account, grant permissions or resolve an error in order to sign in.
   */
  @Override
  public void onConnectionFailed(ConnectionResult result) {
    if (result.getErrorCode() == ConnectionResult.SERVICE_MISSING) { // e.g. emulator without play services installed
      this.savedCallbackContext.error("service not available");
    } else if (loggingOut) {
      loggingOut = false;
      this.savedCallbackContext.success("logged out");
    } else if (result.getErrorCode() == ConnectionResult.SIGN_IN_REQUIRED && !trySilentLogin) {
      final PendingIntent mSignInIntent = result.getResolution();
      try {
        // startIntentSenderForResult is started from the CordovaActivity,
        // set callback to this plugin to make sure this.onActivityResult gets called afterwards
        this.cordova.setActivityResultCallback(this);
        this.cordova.getActivity().startIntentSenderForResult(mSignInIntent.getIntentSender(), 0, null, 0, 0, 0);
      } catch (IntentSender.SendIntentException ignore) {
        mGoogleApiClient.connect();
      }
    } else {
      this.savedCallbackContext.error("no valid token");
    }
  }
  
  @SuppressWarnings({ "unchecked", "rawtypes" })
  private void resolveToken(final String email, final JSONObject result) {
    final Context context = this.cordova.getActivity().getApplicationContext();

    cordova.getThreadPool().execute(new Runnable() {
      public void run() {
        String scope;
        String token;

        try {
          if (GooglePlus.this.webKey != null){
            // Retrieve server side tokens
            scope = "audience:server:client_id:" + GooglePlus.this.webKey;
            token = GoogleAuthUtil.getToken(context, email, scope);
			if(uploadServerAuthCode(token).statusCode == 200) {
				result.put("idToken", token);
			} else {
				 this.savedCallbackContext.error("Error sending the auth code to the server");
			}
          } else if (GooglePlus.this.apiKey != null) {
            // Retrieve the oauth token with offline mode
            scope = "oauth2:server:client_id:" + GooglePlus.this.apiKey;
            scope += ":api_scope:" + Scopes.PLUS_LOGIN;
            token = GoogleAuthUtil.getToken(context, email, scope);
            result.put("oauthToken", token);
          } else {
            // Retrieve the oauth token with offline mode
            scope = "oauth2:" + Scopes.PLUS_LOGIN;
            token = GoogleAuthUtil.getToken(context, email, scope);
            result.put("oauthToken", token);
          }
        }
        catch (UserRecoverableAuthException userAuthEx) {
          // Start the user recoverable action using the intent returned by
          // getIntent()
          cordova.getActivity().startActivityForResult(userAuthEx.getIntent(),
              Activity.RESULT_OK);
          return;
        }
        catch (IOException e) {
          savedCallbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        } catch (GoogleAuthException e) {
          savedCallbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        } catch (JSONException e) {
          savedCallbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        }

        savedCallbackContext.success(result);
      }
    });
  }
  
    private void uploadServerAuthCode(String idToken) {
		HttpClient httpClient = new DefaultHttpClient();
		HttpPost httpPost = new HttpPost(SERVER_AUTH_URL + "auth");
		try {
			httpost.setEntity(new StringEntity(idToken));
			httpost.setHeader("Content-type", "application/octet-stream; charset=utf-8");	

			HttpResponse response = httpClient.execute(httpPost);
			int statusCode = response.getStatusLine().getStatusCode();
			final String responseBody = EntityUtils.toString(response.getEntity());
			 this.savedCallbackContext.error("Code: " + statusCode);
			 this.savedCallbackContext.error("Resp: " + responseBody);
			return (statusCode == 200);
		} catch (ClientProtocolException e) {
			 this.savedCallbackContext.error("Error in auth code exchange.");
			return false;
		} catch (IOException e) {
			 this.savedCallbackContext.error("Error in auth code exchange.");
			return false;
		}
	}
	
	  @Override
	  public void onActivityResult(int requestCode, final int resultCode, final Intent intent) {
		super.onActivityResult(requestCode, resultCode, intent);
		if (resultCode == Activity.RESULT_OK) {
		  mGoogleApiClient.connect();
		} else {
		  this.savedCallbackContext.error("user cancelled");
		}
	  } 
}
