package com.fancy.crackme2;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("ckm");
    }

    public EditText edt;
    public TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        edt = (EditText) findViewById(R.id.edt1);
        tv  = (TextView) findViewById(R.id.TVs);

        Button btn= (Button)findViewById(R.id.bt1);

        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String input=edt.getText().toString().trim();
                int result=tryit(input);
                if(result==15){
                    tv.setText("Success!");
                }
            }
        });

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native int tryit(String input);
}
