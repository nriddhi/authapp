const nodemailer = require('nodemailer');

const mailSend = async(email, subject, message) => {

    try {
		const transporter = nodemailer.createTransport({
			host: process.env.HOST,
			port: Number(process.env.EMAIL_PORT),
			secure: Boolean(process.env.SECURE),
			auth: {
				user: process.env.USER,
				pass: process.env.PASS,
			},
		});

	await transporter.sendMail({
			from: subject,
			to: email,
			subject: 'Verify Your Email',
           html:`${message}`,

		});
	} catch (error) {
		console.log("email not sent!");
		console.log(error);
		return error;
	}


}

module.exports = mailSend;