// Copyright (c) 2018 NETWORK PLATFORM TECHNOLOGIES LIMITED.
//
// This document is the property of NETWORK PLATFORM TECHNOLOGIES LIMITED.
// It is considered confidential and proprietary.
//
// This document may not be reproduced or transmitted in any form,
// in whole or in part, without the express written permission of
// NETWORK PLATFORM TECHNOLOGIES LIMITED.

import 'package:flutter/material.dart';
import 'package:sensitive_info/sensitive_info.dart';

void main() => runApp(new MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => new _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final GlobalKey<ScaffoldState> _scaffold = new GlobalKey<ScaffoldState>();
  final TextEditingController _keyController = new TextEditingController();
  final TextEditingController _valueController = new TextEditingController();

  bool _isSensorAvailable;
  String _availableSensor;

  Map<String, dynamic> _values;

  String _value;

  @override
  initState() {
    super.initState();
    initPlatformState();
  }

  initPlatformState() async {
    bool hasSensor = await SensitiveInfo.isSensorAvailable;
    String availableSensor = await SensitiveInfo.availableSensor;
    setState(() {
      _isSensorAvailable = hasSensor;
      _availableSensor = availableSensor;
    });
  }

  @override
  Widget build(BuildContext context) {
    List<Widget> children = <Widget>[
      _isSensorAvailable == null
          ? const CircularProgressIndicator()
          : new InkWell(
              onTap: () {
                initPlatformState();
              },
              child: new Row(
                children: <Widget>[
                  new Container(
                    margin: const EdgeInsets.all(16.0),
                    child: _isSensorAvailable
                        ? new Icon(
                            Icons.check,
                            color: Colors.green,
                          )
                        : new Icon(
                            Icons.close,
                            color: Colors.red,
                          ),
                  ),
                  new Text('Sensor${_availableSensor == 'none' ? '' : ' $_availableSensor'} is${_isSensorAvailable ? ' ' : ' not '
            }available.'),
                ],
              ),
            ),
      new Container(
        margin: const EdgeInsets.all(16.0),
        child: new TextField(
          controller: _keyController,
          decoration: new InputDecoration(hintText: 'key'),
        ),
      ),
      new Container(
        margin: const EdgeInsets.all(16.0),
        child: new TextField(
          controller: _valueController,
          decoration: new InputDecoration(hintText: 'value'),
        ),
      ),
      new Container(
        margin: const EdgeInsets.all(16.0),
        child: _value == null ? null : new Text("Value for ${_keyController.text} is $_value"),
      )
    ];

    if (_values != null && _values.isNotEmpty) {
      children.add(new Container(
        height: 2.0,
        color: Theme.of(context).dividerColor,
      ));
      children.add(new Text('All keys:'));
      children.add(new Container(
        height: 1.5,
        color: Theme.of(context).dividerColor,
      ));
      for (String key in _values.keys) {
        children.add(new Column(
          children: <Widget>[
            new ListTile(
              title: new Text('$key'),
              onLongPress: () async {
                await SensitiveInfo.deleteItem(key: key);
                final Map<String, dynamic> map = await SensitiveInfo.getAllItems();
                setState(() => _values = map);
              },
            ),
            new Container(
              height: 1.0,
              color: Theme.of(context).dividerColor,
            )
          ],
        ));
      }
    }

    return new MaterialApp(
      home: new Scaffold(
        key: _scaffold,
        appBar: new AppBar(
          title: new Text('Plugin example app'),
          actions: <Widget>[
            new IconButton(
              icon: new Icon(Icons.all_inclusive),
              onPressed: () async {
                final Map<String, dynamic> map = await SensitiveInfo.getAllItems();
                setState(() => _values = map);
              },
            ),
          ],
        ),
        body: new ListView(
          children: children,
        ),
        floatingActionButton: new Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            new Container(
              margin: const EdgeInsets.only(bottom: 8.0),
              child: new FloatingActionButton(
                child: new Icon(Icons.save),
                onPressed: () async {
                  final String key = _keyController.text;
                  final String value = _valueController.text;

                  if (key.isNotEmpty && value.isNotEmpty) {
                    await SensitiveInfo.setItem(
                      key: key,
                      value: value,
                      secAccessControl: IosSecAccessControl.kSecAccessControlBiometryAny,
                    );
                    _scaffold.currentState.showSnackBar(new SnackBar(content: new Text('Data saved.')));
                  } else {
                    _scaffold.currentState.showSnackBar(new SnackBar(content: new Text('Value and Key can\'t be empty.')));
                  }
                },
              ),
            ),
            new FloatingActionButton(
              child: new Icon(Icons.get_app),
              onPressed: () async {
                final String key = _keyController.text;

                if (key.isNotEmpty) {
                  String value = await SensitiveInfo.getItem(
                    key: key,
                    kSecUseOperationPrompt: 'Verifying that\'s indeed you. :))',
                  );

                  if (value == null) {
                    _scaffold.currentState.showSnackBar(new SnackBar(content: new Text('No value for this key.')));
                  } else {
                    setState(() {
                      _value = value;
                    });
                  }
                } else {
                  _scaffold.currentState.showSnackBar(new SnackBar(content: new Text('Key can\'t be empty.')));
                }
              },
            )
          ],
        ),
      ),
    );
  }
}
