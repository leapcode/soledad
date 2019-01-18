The importance of data availability
===================================

Users today demand high data availability in their applications. As a user
switches from device to device, the expectation is that each application will
reflect the same state information across devices. Additionally, if all devices
are lost or destroyed, the contemporary user expects to be able to restore her
or his application data from the cloud.

In many ways, data availability has become a necessary precondition for an
application to be considered "user friendly". Unfortunately, most applications
attempt to provide high data availability by rolling their own custom solution
or relying on a third party API, such as Dropbox. This approach has several
drawbacks: the user has no control or access to the data should they wish to
switch applications or data providers; custom data synchronizations schemes are
often an afterthought, poorly designed, and vulnerable to attack and data
breaches; and the user must place total trust in the provider to safeguard her
or his information against requests by repressive governments.

Soledad provides secure data availability in a way that is easy for application
developers to incorporate into their code.
