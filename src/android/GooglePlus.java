package nl.xservices.plugins;

import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.apache.cordova.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.DefaultHttpClient;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.Activity;
import android.app.Dialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.util.Log;

import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.auth.GooglePlayServicesAvailabilityException;
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
import com.google.android.gms.common.AccountPicker;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.plus.Plus;
import com.google.android.gms.plus.model.people.Person;

public class GooglePlus extends CordovaPlugin implements ConnectionCallbacks, OnConnectionFailedListener {

    private static final String LOG_TAG = "GooglePlusAuth";

    // These are just unique request codes. They can be anything as long as they don't clash.
    private static final int AUTH_REQUEST_CODE = 1;
    private static final int ACCOUNT_CHOOSER_REQUEST_CODE = 2;
    private static final int USER_RECOVERABLE_REQUEST_CODE = 3;
    private static final int UPDATE_GOOGLE_PLAY_SERVICES_REQUEST_CODE = 4;

    // Error codes.
    private static final int ERROR_GOOGLE_PLAY_SERVICES_UNAVAILABLE = -1;
    private static final int ERROR_REQUIRES_USER_INTERACTION = -2;
    private static final int ERROR_NETWORK_UNAVAILABLE = -3;
    private static final int ERROR_USER_CANCELLED = -4;
    private static final int ERROR_CONCURRENT_REQUEST = -5;

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
  private CallbackContext callbackContext;
  private boolean trySilentLogin;
  private boolean loggingOut;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    mGoogleApiClient = buildGoogleApiClient();
  }

  @Override
  public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
    this.callbackContext = callbackContext;

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
      callbackContext.success("" + avail);

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
      callbackContext.success("logged out");

    } else if (ACTION_DISCONNECT.equals(action)) {
      disconnect();
    } else {
      return false;
    }
    return true;
  }
  
  private static String createScopesString(JSONArray scopes) throws JSONException {
        StringBuilder ret = new StringBuilder("oauth2:");

        for (int i = 0; i < scopes.length(); i++) {
            if (i != 0) {
                ret.append(" ");
            }
            ret.append(scopes.getString(i));
        }
        return ret.toString();
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
              callbackContext.success("disconnected");
            }
          });
    } catch (IllegalStateException e) {
      callbackContext.success("disconnected");
    }
  }
    private GoogleApiClient buildGoogleApiClient() {
	return new GoogleApiClient.Builder(webView.getContext())
        .addConnectionCallbacks(this)
        .addOnConnectionFailedListener(this)
        .addApi(Plus.API, Plus.PlusOptions.builder().build())
        .addScope(Plus.SCOPE_PLUS_LOGIN)
	.addScope(Plus.SCOPE_PLUS_PROFILE)
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
      callbackContext.error("result parsing trouble, error: " + e.getMessage());
    }
  }

    @Override
  public void onConnectionSuspended(int constantInClass_ConnectionCallbacks) {
    this.callbackContext.error("connection trouble, code: " + constantInClass_ConnectionCallbacks);
  }

  /**
   * onConnectionFailed is called when our Activity could not connect to Google Play services.
   * onConnectionFailed indicates that the user needs to select an account, grant permissions or resolve an error in order to sign in.
   */
  @Override
  public void onConnectionFailed(ConnectionResult result) {
    if (result.getErrorCode() == ConnectionResult.SERVICE_MISSING) { // e.g. emulator without play services installed
      this.callbackContext.error("service not available");
    } else if (loggingOut) {
      loggingOut = false;
      this.callbackContext.success("logged out");
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
      this.callbackContext.error("no valid token");
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
				 this.callbackContext.error("Error sending the auth code to the server");
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
          callbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        } catch (GoogleAuthException authEx) {
          handleGoogleAuthException(authEx, interactive, callbackContext);
          //callbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        } catch (JSONException e) {
          Log.e(LOG_TAG, "Error occurred while getting token", e);
          callbackContext.error("Failed to retrieve token: " + e.getMessage());
          return;
        }

        callbackContext.success(result);
      }
    });
  }
  
    private void uploadServerAuthCode(String idToken) {
		HttpClient httpClient = new DefaultHttpClient();
		HttpPost httpPost = new HttpPost(serverAuthUrl + "auth");
		try {
			httpost.setEntity(new StringEntity(idToken));
			httpost.setHeader("Content-type", "application/octet-stream; charset=utf-8");	

			HttpResponse response = httpClient.execute(httpPost);
			int statusCode = response.getStatusLine().getStatusCode();
			final String responseBody = EntityUtils.toString(response.getEntity());
			 this.callbackContext.error("Code: " + statusCode);
			 this.callbackContext.error("Resp: " + responseBody);
			return (statusCode == 200);
		} catch (ClientProtocolException e) {
			 this.callbackContext.error("Error in auth code exchange.");
			return false;
		} catch (IOException e) {
			 this.callbackContext.error("Error in auth code exchange.");
			return false;
		}
	}
	
	
	private void handlePlayServicesError(final int errorCode, final boolean interactive, final CallbackContext callbackContext) {
          Log.d(LOG_TAG, "Got PlayServices error: " + errorCode);
          final boolean userRecoverable = GooglePlayServicesUtil.isUserRecoverableError(errorCode);
          if (!interactive) {
              pendingCallDetails = null;
              callbackContext.error(userRecoverable ? ERROR_REQUIRES_USER_INTERACTION : ERROR_GOOGLE_PLAY_SERVICES_UNAVAILABLE);
              return;
          }
          if (errorCode == ConnectionResult.SERVICE_MISSING) {
              // This happens in the emulator where Play Services doesn't exist, or on non-Google Android devices.
              pendingCallDetails = null;
              callbackContext.error(ERROR_GOOGLE_PLAY_SERVICES_UNAVAILABLE);
              return;
          }

        cordova.getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (userRecoverable) {
                    //final CallDetails callDetails = pendingCallDetails;
                    // Need to set the callback manually since the dialog is the one fires the intent.
                    cordova.setActivityResultCallback(GooglePlus.this);
                    Dialog dialog = GooglePlayServicesUtil.getErrorDialog(errorCode, cordova.getActivity(), UPDATE_GOOGLE_PLAY_SERVICES_REQUEST_CODE, new DialogInterface.OnCancelListener() {
                        @Override
                        public void onCancel(DialogInterface dialogInterface) {
                            Log.i(LOG_TAG, "User cancelled the update request");
                            cordova.setActivityResultCallback(null);
                        }
                    });
                    dialog.show();
                } else {
                    Dialog dialog = GooglePlayServicesUtil.getErrorDialog(errorCode, cordova.getActivity(), AUTH_REQUEST_CODE);
                    dialog.show();
                    callbackContext.error(ERROR_GOOGLE_PLAY_SERVICES_UNAVAILABLE);
                    pendingCallDetails = null;
                }
            }
        });
    }

    private void handleGoogleAuthException(GoogleAuthException ex, boolean interactive, CallbackContext callbackContext) {
        if (ex instanceof GooglePlayServicesAvailabilityException) {
            handlePlayServicesError(((GooglePlayServicesAvailabilityException)ex).getConnectionStatusCode(), interactive, callbackContext);
        } else if (ex instanceof UserRecoverableAuthException){
            // OAuth Permissions for the app during first run
            if (interactive) {
                Intent permissionsIntent = ((UserRecoverableAuthException)ex).getIntent();
                cordova.startActivityForResult(this, permissionsIntent, USER_RECOVERABLE_REQUEST_CODE);
            } else {
                Log.e(LOG_TAG, "Recoverable Error occurred while getting token. No action was taken as interactive is set to false", ex);
                callbackContext.error(ERROR_REQUIRES_USER_INTERACTION);
                pendingCallDetails = null;
            }
        } else {
            // This is likely unrecoverable.
            Log.e(LOG_TAG, "Unrecoverable authentication exception.", ex);
            callbackContext.error(ERROR_GOOGLE_PLAY_SERVICES_UNAVAILABLE);
            pendingCallDetails = null;
        }
    }
	
	  @Override
	  public void onActivityResult(int requestCode, final int resultCode, final Intent intent) {
		super.onActivityResult(requestCode, resultCode, intent);
		if (resultCode == Activity.RESULT_OK) {
		  mGoogleApiClient.connect();
		} else {
		  this.callbackContext.error("user cancelled");
		}
	  } 
}
