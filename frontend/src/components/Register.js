import {Link} from "react-router-dom";

export const Register = () => {
    return (
        <div className="container">
            <form>
                <input type="text" placeholder="email"/>
                <input type="password" placeholder="password"/>
                <input type="text" placeholder="firstname"/>
                <input type="text" placeholder="lastname"/>
                <button>Register</button>
                <hr/>
                <button>Continue with github</button>
                <button>Continue with google</button>
                <Link to="/login">Already has an account?</Link>
            </form>
        </div>
    )
}