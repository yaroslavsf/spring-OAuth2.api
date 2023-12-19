import {Link} from "react-router-dom";

export const Login = () => {
    return (
        <div className="container">
            <form>
                <input type="text" placeholder="email"/>
                <input type="password" placeholder="password"/>
                <button>Login</button>
                <hr/>
                <button>Continue with github</button>
                <button>Continue with google</button>
                <Link to="/register">Still no account?</Link>
            </form>
        </div>
    )
}