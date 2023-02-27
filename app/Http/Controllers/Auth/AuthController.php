<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{


    ///////////// Verify //////////////////


    public function verify(Request $request){
        $obj = new \stdClass();

        $validator = Validator::make($request->all(), 
        [
            'platform'=>'required'
        ]);
        if ($validator->fails()) {
                return response()->json([
                    'status' => false,
                    'action' => "Verify failed",
                    'data' => $obj,
                    'error' => $validator->errors()
                 ]);
        }


        if($request->platform == 'normal'){

            $validator = Validator::make($request->all(), 
            [
            'username'=> 'required|unique:users,username',
            'email'=> 'required|email|unique:users,email',
        ]);
         if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'action' => "Verify failed",
                'data' => $obj,
                'error' => $validator->errors()
             ]);
        }
        else{
            $obj->code = 123456;
            return response()->json([
                'status' => true,
                'action' => "Account verify",
                'data' => $obj,
                'error' => $validator->errors()
             ]); 
        }  

        }

        else{
            $validator = Validator::make($request->all(), 
            [
            'email'=> 'required|email|unique:users,email',
        ]);  
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'action' => "Verify failed",
                'data' => $obj,
                'error' => $validator->errors()
             ]);
        }
         else{
            $obj->code = 123456;
            return response()->json([
                'status' => true,
                'action' => "Account verify",
                'data' => $obj,
                'error' => $validator->errors()
             ]); 
        }

        }
    }


     ///////////// Register //////////////////

    public function register(Request $request){
        $obj = new \stdClass();
        $obj1 = new \stdClass();
        $validator = Validator::make($request->all(),
        [
           'email'=> 'required|email',
           'password'=>'required',
           'platform'=> 'required',
           'username'=>'required'
        ]);
        if ($validator->fails()) {
            return response()->json([
            'status' => false,
            'action' => "Register failed",
            'data' => $obj,
            'error' => $validator->errors()
        ]);
    }
    else{
        $user = new User();
        $user->username = $request['username'];
        $user->email = $request['email'];
        $user->password = \Hash::make($request['password']);
        $user->platform = $request['platform'];
        $user->save(); 
        return response()->json([
            'status' => true,
            'action' => "Register successfully",
            'data' => $user,
            'error' => $validator->errors()
         ]);  
    }      

    }


     ///////////// Login //////////////////

    public function login(Request $request){
        $obj = new \stdClass();    
        $obj1 = new \stdClass();    

        $validator = Validator::make($request->all(), 
        [
           'email'=> 'required',
           'password'=>'required'
        ]);
        if ($validator->fails()) {
           return response()->json([
               'status' => false,
               'action' => "Login failed",
               'data' => $obj,
               'error' => $validator->errors()
            ]);
        }
        else{
            $user=User::where('email',$request->email)->orwhere('username',$request->email)->first();
            if($user){
     
             if(\Hash::check($request->password,$user->password)){
                 return response()->json([
                     'status' => true,
                     'action' => "Login successfully",
                     'data' => $user,
                     'error' => $obj1
                  ]);
             }
             else{
             $obj1 = new \stdClass();    
                 $obj1->password = ["wrong password"];
                 return response()->json([
                     'status' => false,
                     'action' => "Login failed",
                     'data' => $obj,
                     'error' => $obj1
                  ]);
             }
         }
         else{
            $obj1 = new \stdClass();    
            $obj1->user = ["User not found"];
            return response()->json([
                'status' => false,
                'action' => "Login failed",
                'data' => $obj,
                'error' => $obj1
            ]);
        }
        }
 
    }


     ///////////// Forgot Password //////////////////


    public function resetAccountVerify(Request $request){
        $obj = new \stdClass();
        $obj1 = new \stdClass();

        $validator = Validator::make($request->all(), 
        [
           'email'=> 'required | email',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'action' => "Password not change",
                'data' => $obj,
                'error' => $validator->errors()
             ]);
        }
        else{
            $user=User::where('email',$request->email)->first();
            if($user){
              
                $obj->code = 123456;
                return response()->json([
                    'status' => true,
                    'action' => 'Account Verify',
                    'data' => $obj,
                    'error' => $validator->errors()
                 ]);
            }
            else{
             $obj1->email = ["Account not Found"];
                return response()->json([
                    'status' => false,
                    'action' => "Password not change",
                    'data' => $obj,
                    'error' => $obj1
                 ]);
            }
        }

    }

    public function resetNewPassword(Request $request){
        $obj = new \stdClass();
        $obj1 = new \stdClass();
        $validator = Validator::make($request->all(), 
        [
           'email'=> 'required | email',
           'newpassword' => 'required'
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'action' => "Password not change",
                'data' => $obj,
                'error' => $validator->errors()
             ]);
        }
        $user=User::where('email',$request->email)->first();
        if($user){
            if(\Hash::check($request->newpassword,$user->password)){
                $obj1->password = 'New password and old password is same';
                return response()->json([
                    'status' => true,
                    'action' => 'Password not change',
                    'data' => $obj,
                    'error' => $obj1
                 ]);
            }
            else{
                $user->update([
                    'password' => \Hash::make($request->newpassword)
                ]);
                return response()->json([
                    'status' => true,
                    'action' => ' Password change',
                    'data' => $obj,
                    'error' => $validator->errors()
                 ]);
            }
        }
    }


     ///////////// Change Password //////////////////



     public function changePassword(Request $request){
        $obj = new \stdClass();
        $obj1 = new \stdClass();

        $validator = Validator::make($request->all(), 
        [
           'email'=> 'required|email',
           'oldpassword'=>'required',
           'newpassword'=>'required'
           
       ]);
       if ($validator->fails()) {
        return response()->json([
            'status' => false,
            'action' => "Password not change",
            'data' => $obj,
            'error' => $validator->errors()
         ]);
        } else{
            $user=User::where('email',$request->email)->first();
            if($user){
             if(\Hash::check($request->oldpassword,$user->password)){
                 $user->update([
                     'password' => \Hash::make($request->newpassword)
                 ]);
                 return response()->json([
                     'status' => true,
                     'action' => "Password change",
                     'data' => $obj,
                     'error' => $validator->errors()
                  ]);
             }
             else{
             $obj1->password = ["Old password is incorrect"];
                 return response()->json([
                     'status' => true,
                     'action' => "Password not change",
                     'data' => $obj,
                     'error' => $obj1
                  ]);
            }
          }
        }
    }
}